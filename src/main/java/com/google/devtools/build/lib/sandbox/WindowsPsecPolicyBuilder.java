// Copyright 2026 The Bazel Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.devtools.build.lib.sandbox;

import static java.util.Comparator.comparing;

import com.google.common.collect.ImmutableList;
import com.google.devtools.build.lib.sandbox.SandboxOptions.WindowsPsecPolicy;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import javax.annotation.Nullable;

/**
 * Computes the path lists of a Windows process security environment for one action.
 *
 * <p>The rules are those the {@code windows-sandbox-mxc} adapter had to discover:
 *
 * <ul>
 *   <li>The execroot is a forest of symlinks and junctions and the kernel evaluates its policy on
 *       the final target of a path, so every grant is also made for its target.
 *   <li>Declared outputs do not exist when the action starts and a grant on a missing file does
 *       not let it be created, so outputs are granted through their parent directory.
 *   <li>A path listed with two intents, or below a path with a weaker intent, gets the most
 *       restrictive one. A read-only grant must therefore never equal or contain a read-write
 *       grant, and an ancestor listed as enumerate-only must not be a grant.
 *   <li>The ancestors of every grant and of the working directory must be enumerable, or nothing
 *       below them can be opened by path or started.
 * </ul>
 *
 * <p>All paths are absolute Windows paths; forward slashes are accepted. Comparisons are
 * case-insensitive. The resulting lists are sorted, so equal policies compare equal and can share
 * one environment.
 */
final class WindowsPsecPolicyBuilder {

  /** Resolves paths to their final targets; an element of the result is null if unresolvable. */
  interface Resolver {
    String[] finalPaths(String[] paths);
  }

  /** A policy: what one security environment allows. Usable as a map key. */
  record Spec(
      ImmutableList<String> readWrite,
      ImmutableList<String> readOnly,
      ImmutableList<String> deny,
      ImmutableList<String> enumerate,
      boolean allowNetwork) {
    int pathCount() {
      return readWrite.size() + readOnly.size() + deny.size() + enumerate.size();
    }
  }

  /** Caches final paths for the life of the builder; safe for concurrent use. */
  static final class CachingResolver implements Resolver {
    private static final String NONE = "";
    private final Resolver delegate;
    private final ConcurrentHashMap<String, String> cache = new ConcurrentHashMap<>();

    CachingResolver(Resolver delegate) {
      this.delegate = delegate;
    }

    @Override
    public String[] finalPaths(String[] paths) {
      String[] result = new String[paths.length];
      List<Integer> missing = new ArrayList<>();
      for (int i = 0; i < paths.length; i++) {
        String cached = cache.get(paths[i]);
        if (cached == null) {
          missing.add(i);
        } else {
          result[i] = cached.equals(NONE) ? null : cached;
        }
      }
      if (!missing.isEmpty()) {
        String[] query = new String[missing.size()];
        for (int i = 0; i < query.length; i++) {
          query[i] = paths[missing.get(i)];
        }
        String[] resolved = delegate.finalPaths(query);
        for (int i = 0; i < query.length; i++) {
          cache.put(query[i], resolved[i] == null ? NONE : resolved[i]);
          result[missing.get(i)] = resolved[i];
        }
      }
      return result;
    }
  }

  private final WindowsPsecPolicy mode;
  private final String execRoot;
  private final Resolver resolver;
  private final ImmutableList<String> readonlyRoots;
  // For COARSE: roots that are granted as a whole.
  private final String outputTree;
  private final String externalRoot;
  private final String tmpRoot;
  private final boolean grantLinks;

  /**
   * @param mode policy granularity
   * @param execRoot the execution root, also the actions' working directory
   * @param outputTree the output tree ({@code <execroot>/bazel-out}); writable as a whole in
   *     COARSE mode
   * @param externalRoot the directory holding the external repositories; readable as a whole in
   *     COARSE mode
   * @param tmpRoot the directory holding the per-action temporary directories; writable as a whole
   *     in COARSE mode
   * @param readonlyRoots extra readable directories (toolchains outside the execroot)
   * @param resolver resolves symlinks and junctions
   * @param grantLinks whether to grant the symlink/junction path in addition to its target
   */
  WindowsPsecPolicyBuilder(
      WindowsPsecPolicy mode,
      String execRoot,
      String outputTree,
      String externalRoot,
      String tmpRoot,
      Collection<String> readonlyRoots,
      Resolver resolver,
      boolean grantLinks) {
    this.mode = mode;
    this.execRoot = win(execRoot);
    this.resolver = resolver;
    this.grantLinks = grantLinks;
    ImmutableList.Builder<String> roots = ImmutableList.builder();
    for (String r : readonlyRoots) {
      roots.add(win(r));
    }
    this.readonlyRoots = roots.build();
    // The roots granted as a whole are granted by their final paths, which is what the kernel
    // compares against.
    this.outputTree = resolveOne(win(outputTree));
    this.externalRoot = resolveOne(win(externalRoot));
    this.tmpRoot = win(tmpRoot);
  }

  /**
   * Builds the policy of one action.
   *
   * @param inputFiles declared input files
   * @param inputDirs declared input directories (runfiles trees)
   * @param outputFiles declared output files
   * @param outputDirs declared output directories, and writable directories such as the action's
   *     temporary directory
   * @param deny paths the action must not access
   */
  Spec build(
      Collection<String> inputFiles,
      Collection<String> inputDirs,
      Collection<String> outputFiles,
      Collection<String> outputDirs,
      Collection<String> deny,
      boolean allowNetwork) {
    // Read-write grants. Outputs never exist when the action starts.
    List<String> rw = new ArrayList<>();
    for (String f : outputFiles) {
      rw.add(parent(win(f)));
    }
    for (String d : outputDirs) {
      String dir = win(d);
      // Outside PRECISE mode the per-action temporary directory is granted through the temp
      // root, or no two actions would ever have the same policy.
      if (mode != WindowsPsecPolicy.PRECISE && isSameOrUnder(key(dir), key(tmpRoot))) {
        dir = tmpRoot;
      }
      rw.add(dir);
    }

    List<String> roFiles = new ArrayList<>(inputFiles.size());
    for (String f : inputFiles) {
      roFiles.add(win(f));
    }
    List<String> roDirs = new ArrayList<>(inputDirs.size() + readonlyRoots.size());
    for (String d : inputDirs) {
      roDirs.add(win(d));
    }
    roDirs.addAll(readonlyRoots);

    Map<String, String> targets = resolveAll(roFiles, roDirs, rw);

    List<String> ro = new ArrayList<>();
    if (mode == WindowsPsecPolicy.COARSE) {
      List<String> coarseRw = new ArrayList<>();
      coarseRw.add(outputTree);
      coarseRw.add(tmpRoot);
      for (String r : withTargets(rw, targets)) {
        if (!isSameOrUnder(key(r), key(outputTree)) && !isSameOrUnder(key(r), key(tmpRoot))) {
          coarseRw.add(r);
        }
      }
      rw = coarseRw;
      Map<String, String> prefixTargets = new HashMap<>();
      for (String f : roFiles) {
        coarsen(f, targets.getOrDefault(f, f), prefixTargets, ro);
      }
      for (String d : roDirs) {
        coarsen(d, targets.getOrDefault(d, d), prefixTargets, ro);
      }
    } else {
      rw = withTargets(rw, targets);
      List<String> files = withTargets(roFiles, targets);
      if (mode == WindowsPsecPolicy.DIRECTORIES) {
        List<String> rwKeys = keys(rw);
        for (String f : files) {
          String dir = parent(f);
          ro.add(containsAny(key(dir), rwKeys) ? f : dir);
        }
      } else {
        ro.addAll(files);
      }
      ro.addAll(withTargets(roDirs, targets));
    }

    // Most restrictive intent wins: a read-only grant must not equal or contain a read-write one.
    // Outside PRECISE mode, read-only grants under a read-write one are redundant too.
    List<String> rwKeys = keys(rw);
    List<String> keptRo = new ArrayList<>(ro.size());
    for (String r : ro) {
      String k = key(r);
      if (containsAny(k, rwKeys)) {
        continue;
      }
      if (mode != WindowsPsecPolicy.PRECISE && isUnderAny(k, rwKeys)) {
        continue;
      }
      keptRo.add(r);
    }
    ImmutableList<String> readOnly = pruneNested(keptRo);
    ImmutableList<String> readWrite = pruneNested(rw);
    ImmutableList<String> denied = pruneNested(winAll(deny));

    // Enumerate the ancestors of every grant, and the working directory itself, top-down until a
    // grant covers them.
    Set<String> grantKeys = new HashSet<>();
    for (String g : readOnly) {
      grantKeys.add(key(g));
    }
    for (String g : readWrite) {
      grantKeys.add(key(g));
    }
    Map<String, String> enumerate = new LinkedHashMap<>();
    for (String g : readOnly) {
      addAncestors(parentOrNull(g), grantKeys, enumerate);
    }
    for (String g : readWrite) {
      addAncestors(parentOrNull(g), grantKeys, enumerate);
    }
    addAncestors(execRoot, grantKeys, enumerate);
    List<String> enumerated = new ArrayList<>(enumerate.values());
    enumerated.sort(comparing(WindowsPsecPolicyBuilder::key));

    return new Spec(
        readWrite, readOnly, denied, ImmutableList.copyOf(enumerated), allowNetwork);
  }

  /** Maps a readable path to the coarse grant that covers it. */
  private void coarsen(
      String path, String target, Map<String, String> prefixTargets, List<String> ro) {
    String targetKey = key(target);
    if (isSameOrUnder(targetKey, key(outputTree)) || isSameOrUnder(targetKey, key(tmpRoot))) {
      return; // Writable anyway.
    }
    String prefix = execRootPrefix(path);
    if (prefix == null) {
      // Not in the execroot: a toolchain root or similar, granted as given.
      ro.add(path);
      if (!key(path).equals(targetKey)) {
        ro.add(target);
      }
      return;
    }
    String prefixTarget = prefixTargets.computeIfAbsent(prefix, this::resolveOne);
    if (isSameOrUnder(targetKey, key(prefixTarget))) {
      if (!externalRoot.isEmpty() && isSameOrUnder(key(prefixTarget), key(externalRoot))) {
        ro.add(externalRoot);
      } else {
        ro.add(prefixTarget);
      }
      if (grantLinks && !key(prefix).equals(key(prefixTarget))) {
        ro.add(prefix);
      }
    } else {
      // A link deeper in the tree points elsewhere; grant the target's directory.
      ro.add(parent(target));
      if (grantLinks) {
        ro.add(path);
      }
    }
  }

  /**
   * The execroot entry a path lies in: {@code <execroot>\external\<repo>} for external
   * repositories, {@code <execroot>\<first segment>} otherwise, or the path itself for a file at
   * the top of the execroot. Null if the path is not below the execroot.
   */
  @Nullable
  private String execRootPrefix(String path) {
    String k = key(path);
    String rootKey = key(execRoot);
    if (!isUnder(k, rootKey)) {
      return null;
    }
    int start = rootKey.length() + (rootKey.endsWith("\\") ? 0 : 1);
    int end = path.indexOf('\\', start);
    if (end < 0) {
      return path;
    }
    if (k.substring(start, end).equals("external")) {
      int repoEnd = path.indexOf('\\', end + 1);
      return repoEnd < 0 ? path : path.substring(0, repoEnd);
    }
    return path.substring(0, end);
  }

  private Map<String, String> resolveAll(List<String> a, List<String> b, List<String> c) {
    String[] all = new String[a.size() + b.size() + c.size()];
    int i = 0;
    for (String p : a) {
      all[i++] = p;
    }
    for (String p : b) {
      all[i++] = p;
    }
    for (String p : c) {
      all[i++] = p;
    }
    String[] finals = resolver.finalPaths(all);
    Map<String, String> targets = new HashMap<>();
    for (int j = 0; j < all.length; j++) {
      if (finals[j] != null && !key(finals[j]).equals(key(all[j]))) {
        targets.put(all[j], win(finals[j]));
      }
    }
    return targets;
  }

  private String resolveOne(String path) {
    String[] finals = resolver.finalPaths(new String[] {path});
    return finals[0] != null ? win(finals[0]) : path;
  }

  /** The paths followed by the targets of those that are links. */
  private List<String> withTargets(List<String> paths, Map<String, String> targets) {
    List<String> result = new ArrayList<>(paths.size());
    List<String> extra = new ArrayList<>();
    for (String p : paths) {
      String t = targets.get(p);
      if (t == null) {
        result.add(p);
      } else {
        if (grantLinks) {
          result.add(p);
        }
        extra.add(t);
      }
    }
    result.addAll(extra);
    return result;
  }

  private static void addAncestors(
      @Nullable String dir, Set<String> grantKeys, Map<String, String> enumerate) {
    List<String> chain = new ArrayList<>();
    for (String d = dir; d != null; d = parentOrNull(d)) {
      chain.add(d);
    }
    for (int i = chain.size() - 1; i >= 0; i--) {
      String k = key(chain.get(i));
      if (grantKeys.contains(k)) {
        return; // Covered by a grant, and so is everything below.
      }
      enumerate.putIfAbsent(k, chain.get(i));
    }
  }

  /**
   * Dedupes and drops paths inside another path of the same list; sorted by key, in {@link #win}
   * form. Of paths that differ only in case, the first one is kept.
   */
  static ImmutableList<String> pruneNested(Collection<String> paths) {
    List<String> sorted = new ArrayList<>(paths);
    sorted.sort(comparing(WindowsPsecPolicyBuilder::key));
    ImmutableList.Builder<String> result = ImmutableList.builder();
    String lastKept = null;
    for (String p : sorted) {
      String k = key(p);
      if (lastKept != null && isSameOrUnder(k, lastKept)) {
        continue;
      }
      lastKept = k;
      result.add(win(p));
    }
    return result.build();
  }

  private static List<String> keys(Collection<String> paths) {
    List<String> result = new ArrayList<>(paths.size());
    for (String p : paths) {
      result.add(key(p));
    }
    return result;
  }

  private static List<String> winAll(Collection<String> paths) {
    List<String> result = new ArrayList<>(paths.size());
    for (String p : paths) {
      result.add(win(p));
    }
    return result;
  }

  private static boolean containsAny(String dirKey, List<String> keys) {
    for (String k : keys) {
      if (isSameOrUnder(k, dirKey)) {
        return true;
      }
    }
    return false;
  }

  private static boolean isUnderAny(String k, List<String> dirKeys) {
    for (String d : dirKeys) {
      if (isUnder(k, d)) {
        return true;
      }
    }
    return false;
  }

  /** Backslashes, no trailing separator except on a drive root. */
  static String win(String p) {
    String s = p.replace('/', '\\');
    while (s.length() > 3 && s.endsWith("\\")) {
      s = s.substring(0, s.length() - 1);
    }
    return s;
  }

  /** Comparison key: {@link #win} and lower case. */
  static String key(String p) {
    return win(p).toLowerCase(Locale.ROOT);
  }

  static boolean isUnder(String childKey, String dirKey) {
    return childKey.length() > dirKey.length()
        && childKey.startsWith(dirKey)
        && (dirKey.endsWith("\\") || childKey.charAt(dirKey.length()) == '\\');
  }

  static boolean isSameOrUnder(String childKey, String dirKey) {
    return childKey.equals(dirKey) || isUnder(childKey, dirKey);
  }

  /** The parent directory; a drive root is its own parent. */
  static String parent(String p) {
    String parent = parentOrNull(p);
    return parent != null ? parent : p;
  }

  @Nullable
  static String parentOrNull(String p) {
    int i = p.lastIndexOf('\\');
    if (i < 0 || p.length() <= 3) {
      return null;
    }
    return i <= 2 ? p.substring(0, 3) : p.substring(0, i);
  }
}
