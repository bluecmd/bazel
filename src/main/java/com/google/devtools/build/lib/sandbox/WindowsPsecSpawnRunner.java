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

import com.google.common.base.Joiner;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.devtools.build.lib.actions.ActionInput;
import com.google.devtools.build.lib.actions.Artifact;
import com.google.devtools.build.lib.actions.Spawn;
import com.google.devtools.build.lib.actions.Spawns;
import com.google.devtools.build.lib.events.Event;
import com.google.devtools.build.lib.events.EventKind;
import com.google.devtools.build.lib.events.Reporter;
import com.google.devtools.build.lib.profiler.Profiler;
import com.google.devtools.build.lib.profiler.SilentCloseable;
import com.google.devtools.build.lib.runtime.CommandEnvironment;
import com.google.devtools.build.lib.sandbox.SandboxHelpers.SandboxInputs;
import com.google.devtools.build.lib.sandbox.SandboxOptions.WindowsPsecPolicy;
import com.google.devtools.build.lib.sandbox.WindowsPsecPolicyBuilder.Spec;
import com.google.devtools.build.lib.vfs.Path;
import com.google.devtools.build.lib.vfs.PathFragment;
import com.google.devtools.build.lib.windows.WindowsPsec;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import javax.annotation.Nullable;

/**
 * Runs actions in Windows process security environments, created by the Bazel server itself
 * through JNI ({@code processmodel.dll}, Windows 11 25H2 build 26200.9550 and later).
 *
 * <p>The policy is built from the action's declared inputs and outputs; see {@link
 * WindowsPsecPolicyBuilder} for the rules and {@link WindowsPsecPolicy} for the granularities.
 * Environments are pooled by policy ({@link WindowsPsecEnvironmentPool}) and attached to the
 * action's process at {@code CreateProcessW} time, so there is no helper binary and no extra
 * process per action.
 */
final class WindowsPsecSpawnRunner extends AbstractSandboxSpawnRunner {

  private final Path execRoot;
  private final Path tmpRoot;
  private final Reporter reporter;
  private final ImmutableMap<String, String> clientEnv;
  private final WindowsPsecPolicyBuilder policyBuilder;
  private final WindowsPsecEnvironmentPool pool;
  private final boolean allowNetworkForBuild;
  private final boolean debug;
  private final WindowsPsecPolicy mode;
  private final boolean clientFs;
  private final AtomicLong nextId = new AtomicLong();

  /** Returns null if the strategy can be used on this machine, otherwise why not. */
  @Nullable
  static String checkSupport() {
    try {
      return WindowsPsec.checkSupport();
    } catch (UnsatisfiedLinkError e) {
      return "the Windows JNI library lacks process security environment support: " + e;
    }
  }

  WindowsPsecSpawnRunner(
      CommandEnvironment cmdEnv,
      WindowsPsecPolicy mode,
      List<PathFragment> readonlyRoots,
      int maxIdleEnvironments,
      boolean clientFs,
      int spareEnvironments,
      boolean debug)
      throws IOException {
    super(cmdEnv);
    this.execRoot = cmdEnv.getExecRoot();
    this.reporter = cmdEnv.getReporter();
    this.clientEnv = cmdEnv.getClientEnv();
    // Short on purpose: zipped py_binary tools extract their runfiles under TMPDIR and exceed
    // MAX_PATH from a deeper directory (the user's %TEMP%, which local actions get, is about as
    // long as this).
    this.tmpRoot = cmdEnv.getDirectories().getOutputBase().getRelative("psec");
    this.tmpRoot.createDirectoryAndParents();
    this.allowNetworkForBuild = SandboxHelpers.shouldAllowNetwork(cmdEnv.getOptions());
    this.debug = debug;
    this.mode = mode;
    this.clientFs = clientFs;
    List<String> roots = new ArrayList<>();
    for (PathFragment root : readonlyRoots) {
      roots.add(root.getPathString());
    }
    WindowsPsecPolicyBuilder.Resolver resolver =
        new WindowsPsecPolicyBuilder.CachingResolver(WindowsPsec::getFinalPaths);
    this.policyBuilder =
        new WindowsPsecPolicyBuilder(
            mode,
            execRoot.getPathString(),
            cmdEnv.getDirectories().getOutputPath(cmdEnv.getWorkspaceName()).getPathString(),
            cmdEnv.getDirectories().getOutputBase().getRelative("external").getPathString(),
            tmpRoot.getPathString(),
            roots,
            resolver,
            !Boolean.getBoolean("bazel.windows_psec.no_link_grants"));
    this.pool =
        new WindowsPsecEnvironmentPool(
            new WindowsPsecEnvironmentPool.EnvironmentFactory() {
              @Override
              public long create(Spec spec) throws IOException {
                try (SilentCloseable c = Profiler.instance().profile("psec.createEnvironment")) {
                  return WindowsPsec.createEnvironment(
                      spec.readWrite(),
                      spec.readOnly(),
                      spec.deny(),
                      spec.enumerate(),
                      /* disallowWin32k= */ false,
                      WindowsPsec.DESKTOP_UI_RESTRICTIONS,
                      spec.allowNetwork(),
                      clientFs);
                }
              }

              @Override
              public void close(long handle) {
                WindowsPsec.closeEnvironment(handle);
              }

              @Override
              public boolean supportsBlank() {
                return clientFs;
              }

              @Override
              public long createBlank(boolean allowNetwork) throws IOException {
                try (SilentCloseable c = Profiler.instance().profile("psec.createBlank")) {
                  return WindowsPsec.createBlankEnvironment(
                      /* disallowWin32k= */ false,
                      WindowsPsec.DESKTOP_UI_RESTRICTIONS,
                      allowNetwork);
                }
              }

              @Override
              public void apply(long handle, Spec spec) throws IOException {
                try (SilentCloseable c = Profiler.instance().profile("psec.applyPolicy")) {
                  WindowsPsec.applyFilesystem(
                      handle, spec.readWrite(), spec.readOnly(), spec.deny(), spec.enumerate());
                }
              }

              @Override
              public void clear(long handle) throws IOException {
                WindowsPsec.clearFilesystem(handle);
              }
            },
            maxIdleEnvironments,
            spareEnvironments);
  }

  @Override
  protected SandboxedSpawn prepareSpawn(Spawn spawn, SpawnExecutionContext context)
      throws IOException, InterruptedException {
    Path tmpDir = tmpRoot.getChild(Long.toString(nextId.incrementAndGet()));
    tmpDir.createDirectoryAndParents();
    ImmutableMap<String, String> environment =
        actionEnvironment(spawn.getEnvironment(), tmpDir.getPathString().replace('/', '\\'));

    SandboxInputs inputs =
        SandboxHelpers.processInputFiles(
            context.getInputMapping(/* willAccessRepeatedly= */ true), execRoot);
    if (!inputs.getSymlinks().isEmpty()) {
      throw new IOException(
          "windows-psec does not support unresolved symlinks yet ("
              + Joiner.on(", ").join(inputs.getSymlinks().keySet())
              + ")");
    }

    List<String> inputFiles = new ArrayList<>(inputs.getFiles().size());
    for (Path p : inputs.getFiles().values()) {
      if (p != null) { // Empty virtual inputs.
        inputFiles.add(p.getPathString());
      }
    }
    // The input mapping expands runfiles trees to their files, but the action reaches them
    // through the <tool>.runfiles directory, which must be traversable.
    List<String> inputDirs = new ArrayList<>();
    for (ActionInput input : spawn.getInputFiles().toList()) {
      if (input instanceof Artifact artifact && artifact.isRunfilesTree()) {
        inputDirs.add(execRoot.getRelative(artifact.getExecPath()).getPathString());
      }
    }
    List<String> outputFiles = new ArrayList<>();
    List<String> outputDirs = new ArrayList<>();
    for (ActionInput output : spawn.getOutputFiles()) {
      String path = execRoot.getRelative(output.getExecPath()).getPathString();
      if (output instanceof Artifact artifact && artifact.isTreeArtifact()) {
        outputDirs.add(path);
      } else {
        outputFiles.add(path);
      }
    }
    for (Path p : getWritableDirs(execRoot, environment)) {
      outputDirs.add(p.getPathString());
    }
    List<String> deny = new ArrayList<>();
    for (Path p : getInaccessiblePaths()) {
      deny.add(p.getPathString());
    }
    // Network is denied unless the action asks for it with `requires-network`.
    // --sandbox_default_allow_network is not honoured: its default (true) would turn the
    // deny-by-default policy into allow-by-default.
    boolean allowNetwork =
        allowNetworkForBuild
            || Spawns.requiresNetwork(spawn, /* defaultSandboxDisallowNetwork= */ false);

    Spec spec;
    try (SilentCloseable c = Profiler.instance().profile("psec.buildPolicy")) {
      spec =
          policyBuilder.build(inputFiles, inputDirs, outputFiles, outputDirs, deny, allowNetwork);
    }
    WindowsPsecEnvironmentPool.Lease lease;
    try (SilentCloseable c = Profiler.instance().profile("psec.acquireEnvironment")) {
      lease = pool.acquire(spec);
    }
    if (debug) {
      reporter.handle(
          Event.of(
              EventKind.DEBUG,
              String.format(
                  "windows-psec policy for %s %s (%s environment):\n%s",
                  spawn.getMnemonic(),
                  spawn.getTargetLabel(),
                  lease.created() ? "new" : "reused",
                  describe(spec))));
    }

    return new WindowsPsecSandboxedSpawn(
        execRoot,
        environment,
        absoluteArgv0(spawn.getArguments()),
        spawn.getMnemonic(),
        tmpDir,
        lease);
  }

  /**
   * The action's environment, plus what process security environments need: Windows rewrites
   * TEMP/TMP/LOCALAPPDATA inside a security environment to a per-environment {@code AC\Temp}, so
   * TMPDIR (which Windows leaves alone and Python's tempfile prefers) points to the action's own
   * temporary directory; and CreateProcessW refuses to start a process in a security environment
   * without USERPROFILE and LOCALAPPDATA in its environment.
   */
  private ImmutableMap<String, String> actionEnvironment(Map<String, String> env, String tmp) {
    Map<String, String> result = new LinkedHashMap<>();
    for (Map.Entry<String, String> e : env.entrySet()) {
      String k = e.getKey().toUpperCase(Locale.ROOT);
      if (!k.equals("TMP") && !k.equals("TEMP") && !k.equals("TMPDIR")) {
        result.put(e.getKey(), e.getValue());
      }
    }
    result.put("TMP", tmp);
    result.put("TEMP", tmp);
    result.put("TMPDIR", tmp);
    String home = clientEnv.get("USERPROFILE");
    if (home == null) {
      home = System.getProperty("user.home", "C:\\Users\\Default");
    }
    putIfAbsentIgnoreCase(result, "USERPROFILE", home);
    String localAppData = clientEnv.get("LOCALAPPDATA");
    putIfAbsentIgnoreCase(
        result, "LOCALAPPDATA", localAppData != null ? localAppData : home + "\\AppData\\Local");
    return ImmutableMap.copyOf(result);
  }

  private static void putIfAbsentIgnoreCase(Map<String, String> env, String name, String value) {
    for (String k : env.keySet()) {
      if (k.equalsIgnoreCase(name)) {
        return;
      }
    }
    env.put(name, value);
  }

  /**
   * Resolves a relative argv[0] that contains a separator against the execroot, as the local
   * runner does. Batch files otherwise fail: cmd.exe parses the '/' in {@code external/foo.bat}
   * as a switch.
   */
  private ImmutableList<String> absoluteArgv0(ImmutableList<String> args) {
    File argv0 = new File(args.get(0));
    if (argv0.isAbsolute() || argv0.getParent() == null) {
      return args;
    }
    List<String> newArgs = new ArrayList<>(args);
    newArgs.set(0, new File(execRoot.getPathFile(), args.get(0)).getAbsolutePath());
    return ImmutableList.copyOf(newArgs);
  }

  private static String describe(Spec spec) {
    StringBuilder s = new StringBuilder();
    for (String p : spec.readWrite()) {
      s.append("  rw ").append(p).append('\n');
    }
    for (String p : spec.readOnly()) {
      s.append("  ro ").append(p).append('\n');
    }
    for (String p : spec.deny()) {
      s.append("  deny ").append(p).append('\n');
    }
    for (String p : spec.enumerate()) {
      s.append("  enum ").append(p).append('\n');
    }
    s.append("  network ").append(spec.allowNetwork() ? "allow" : "deny");
    return s.toString();
  }

  /** Closes all environments and reports how they were used. Call when no action runs. */
  void close() {
    long creates = pool.creates.get();
    long reuses = pool.reuses.get();
    if (creates + reuses > 0) {
      reporter.handle(
          Event.info(
              String.format(
                  "windows-psec (%s, %s): %d actions, %d policies set up (%.1f s, %d paths), %d"
                      + " actions reused one",
                  mode.name().toLowerCase(Locale.ROOT),
                  clientFs ? "client-side policy" : "service-side policy",
                  creates + reuses,
                  creates,
                  pool.createNanos.get() / 1e9,
                  pool.createdPaths.get(),
                  reuses)));
      if (clientFs) {
        // Starvation: a policy that found no blank environment ready had to wait for a
        // CreateProcessSecurityEnvironment round trip.
        reporter.handle(
            Event.info(
                String.format(
                    "windows-psec environment stock: %d security environments created (%d ahead,"
                        + " %d inline); %d policies set up on a ready environment, %d recycled"
                        + " environments returned to the stock, %d starved (created inline, %.1f s);"
                        + " actions waited %.1f s in total for an environment, at most %d ms",
                    pool.refilled.get() + pool.starved.get(),
                    pool.refilled.get(),
                    pool.starved.get(),
                    pool.fromStock.get(),
                    pool.recycled.get(),
                    pool.starved.get(),
                    pool.starvedNanos.get() / 1e9,
                    pool.acquireNanos.get() / 1e9,
                    pool.maxAcquireNanos.get() / 1_000_000)));
      }
    }
    pool.close();
    try {
      tmpRoot.deleteTree();
    } catch (IOException e) {
      // Best effort; per-action directories are removed as actions finish.
    }
  }

  @Override
  public String getName() {
    return "windows-psec";
  }
}
