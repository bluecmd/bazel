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

import static com.google.common.truth.Truth.assertThat;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.devtools.build.lib.sandbox.SandboxOptions.WindowsPsecPolicy;
import com.google.devtools.build.lib.sandbox.WindowsPsecPolicyBuilder.Spec;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link WindowsPsecPolicyBuilder}. Pure path logic, so it runs on every platform. */
@RunWith(JUnit4.class)
public final class WindowsPsecPolicyBuilderTest {

  private static final String EXEC = "C:\\ob\\execroot\\_main";
  private static final String TMP = "C:\\ob\\sandbox\\windows-psec";

  // The execroot's symlink forest: top-level source entries point into the workspace, external
  // repositories into the output base.
  private static final ImmutableMap<String, String> LINKS =
      ImmutableMap.of(
          EXEC + "\\src", "C:\\ws\\src",
          EXEC + "\\third_party", "C:\\ws\\third_party",
          EXEC + "\\secret.txt", "C:\\ws\\secret.txt",
          EXEC + "\\BUILD", "C:\\ws\\BUILD",
          EXEC + "\\external\\repo", "C:\\ob\\external\\repo",
          EXEC + "\\external\\bazel_tools", "C:\\install\\embedded_tools",
          "C:\\ws\\src\\link.h", "C:\\elsewhere\\real.h");

  private final AtomicInteger resolverCalls = new AtomicInteger();

  private String[] resolve(String[] paths) {
    resolverCalls.incrementAndGet();
    String[] result = new String[paths.length];
    for (int i = 0; i < paths.length; i++) {
      result[i] = resolveOne(paths[i]);
    }
    return result;
  }

  private static String resolveOne(String path) {
    String p = path.replace('/', '\\');
    // Resolve repeatedly, so links inside link targets are followed too.
    for (boolean changed = true; changed; ) {
      changed = false;
      for (Map.Entry<String, String> link : LINKS.entrySet()) {
        String k = link.getKey().toLowerCase(Locale.ROOT);
        String lower = p.toLowerCase(Locale.ROOT);
        if (lower.equals(k) || lower.startsWith(k + "\\")) {
          p = link.getValue() + p.substring(k.length());
          changed = true;
        }
      }
    }
    return p;
  }

  private WindowsPsecPolicyBuilder builder(WindowsPsecPolicy mode, boolean grantLinks) {
    return new WindowsPsecPolicyBuilder(
        mode,
        EXEC,
        EXEC + "\\bazel-out",
        "C:\\ob\\external",
        TMP,
        ImmutableList.of("C:\\VS", "C:/Kits/"),
        new WindowsPsecPolicyBuilder.CachingResolver(this::resolve),
        grantLinks);
  }

  private static Spec build(
      WindowsPsecPolicyBuilder b, List<String> inputs, List<String> outputs, String tmp) {
    return b.build(
        inputs,
        ImmutableList.of(),
        outputs,
        ImmutableList.of(tmp),
        ImmutableList.of(),
        /* allowNetwork= */ false);
  }

  @Test
  public void precise_grantsFilesAndTheirTargets() {
    Spec spec =
        build(
            builder(WindowsPsecPolicy.PRECISE, true),
            ImmutableList.of(EXEC + "/src/a/b.c", EXEC + "\\src\\link.h"),
            ImmutableList.of(EXEC + "\\bazel-out\\bin\\a\\b.o"),
            TMP + "\\1");

    assertThat(spec.readOnly())
        .containsExactly(
            "C:\\elsewhere\\real.h",
            "C:\\Kits",
            EXEC + "\\src\\a\\b.c",
            EXEC + "\\src\\link.h",
            "C:\\VS",
            "C:\\ws\\src\\a\\b.c")
        .inOrder();
    assertThat(spec.readWrite())
        .containsExactly(EXEC + "\\bazel-out\\bin\\a", TMP + "\\1")
        .inOrder();
    assertThat(spec.enumerate())
        .containsExactly(
            "C:\\",
            "C:\\elsewhere",
            "C:\\ob",
            "C:\\ob\\execroot",
            EXEC,
            EXEC + "\\bazel-out",
            EXEC + "\\bazel-out\\bin",
            EXEC + "\\src",
            EXEC + "\\src\\a",
            "C:\\ob\\sandbox",
            TMP,
            "C:\\ws",
            "C:\\ws\\src",
            "C:\\ws\\src\\a")
        .inOrder();
    assertThat(spec.allowNetwork()).isFalse();
  }

  @Test
  public void readOnlyGrantNeverContainsReadWriteGrant() {
    Spec spec =
        builder(WindowsPsecPolicy.PRECISE, true)
            .build(
                ImmutableList.of(EXEC + "\\bazel-out\\bin\\pkg\\in.txt"),
                ImmutableList.of(EXEC + "\\bazel-out\\bin\\pkg"),
                ImmutableList.of(EXEC + "\\bazel-out\\bin\\pkg\\out.txt"),
                ImmutableList.of(TMP + "\\1"),
                ImmutableList.of(),
                false);

    // The runfiles-like input directory equals the output's directory: dropped. The input file
    // inside it stays read-only, as in the adapter.
    assertThat(spec.readWrite()).contains(EXEC + "\\bazel-out\\bin\\pkg");
    assertThat(spec.readOnly()).doesNotContain(EXEC + "\\bazel-out\\bin\\pkg");
    assertThat(spec.readOnly()).contains(EXEC + "\\bazel-out\\bin\\pkg\\in.txt");
    for (String e : spec.enumerate()) {
      assertThat(spec.readWrite()).doesNotContain(e);
      assertThat(spec.readOnly()).doesNotContain(e);
    }
  }

  @Test
  public void directories_grantsParentsUnlessTheyHoldOutputs() {
    Spec spec =
        build(
            builder(WindowsPsecPolicy.DIRECTORIES, false),
            ImmutableList.of(
                EXEC + "\\src\\a\\b.c",
                EXEC + "\\src\\a\\c.h",
                EXEC + "\\bazel-out\\bin\\a\\gen.h",
                EXEC + "\\bazel-out\\bin\\x\\dep.h"),
            ImmutableList.of(EXEC + "\\bazel-out\\bin\\a\\b.o"),
            TMP + "\\1");

    assertThat(spec.readOnly())
        .containsExactly(
            "C:\\Kits", EXEC + "\\bazel-out\\bin\\x", "C:\\VS", "C:\\ws\\src\\a")
        .inOrder();
    // bin\a holds the output: gen.h is covered by the read-write grant. The per-action temp
    // directory is granted through the temp root, so policies can be shared.
    assertThat(spec.readWrite()).containsExactly(EXEC + "\\bazel-out\\bin\\a", TMP).inOrder();
  }

  @Test
  public void directories_actionsWithTheSameDirectoriesShareOnePolicy() {
    WindowsPsecPolicyBuilder b = builder(WindowsPsecPolicy.DIRECTORIES, false);
    Spec one =
        build(
            b,
            ImmutableList.of(EXEC + "\\src\\a\\b.c", EXEC + "\\src\\a\\b.h"),
            ImmutableList.of(EXEC + "\\bazel-out\\bin\\a\\_objs\\b.obj"),
            TMP + "\\1");
    Spec two =
        build(
            b,
            ImmutableList.of(EXEC + "\\src\\a\\c.c", EXEC + "\\src\\a\\b.h"),
            ImmutableList.of(EXEC + "\\bazel-out\\bin\\a\\_objs\\c.obj"),
            TMP + "\\2");
    assertThat(one).isEqualTo(two);
  }

  @Test
  public void coarse_grantsTopLevelSourceDirsAndWholeOutputTree() {
    WindowsPsecPolicyBuilder b = builder(WindowsPsecPolicy.COARSE, false);
    Spec spec =
        build(
            b,
            ImmutableList.of(
                EXEC + "\\src\\a\\b.c",
                EXEC + "\\src\\b\\c.h",
                EXEC + "\\BUILD",
                EXEC + "\\external\\repo\\x.h",
                EXEC + "\\external\\bazel_tools\\tools\\t.bat",
                EXEC + "\\bazel-out\\bin\\gen.h"),
            ImmutableList.of(EXEC + "\\bazel-out\\bin\\a\\b.o"),
            TMP + "\\7");

    assertThat(spec.readOnly())
        .containsExactly(
            "C:\\install\\embedded_tools",
            "C:\\Kits",
            "C:\\ob\\external",
            "C:\\VS",
            "C:\\ws\\BUILD",
            "C:\\ws\\src")
        .inOrder();
    assertThat(spec.readWrite()).containsExactly(EXEC + "\\bazel-out", TMP).inOrder();
    // secret.txt sits next to BUILD in the workspace but is not granted.
    assertThat(spec.readOnly()).doesNotContain("C:\\ws");
  }

  @Test
  public void coarse_actionsInTheSameTopLevelDirsShareOnePolicy() {
    WindowsPsecPolicyBuilder b = builder(WindowsPsecPolicy.COARSE, false);
    Spec one =
        build(
            b,
            ImmutableList.of(EXEC + "\\src\\a\\b.c", EXEC + "\\external\\repo\\x.h"),
            ImmutableList.of(EXEC + "\\bazel-out\\bin\\a\\b.o"),
            TMP + "\\1");
    Spec two =
        build(
            b,
            ImmutableList.of(EXEC + "\\src\\z\\y.c", EXEC + "\\src\\z\\y.h"),
            ImmutableList.of(EXEC + "\\bazel-out\\bin\\z\\y.o", EXEC + "\\bazel-out\\bin\\z\\y.d"),
            TMP + "\\2");
    Spec three =
        build(
            b,
            ImmutableList.of(EXEC + "\\third_party\\q.c"),
            ImmutableList.of(EXEC + "\\bazel-out\\bin\\q.o"),
            TMP + "\\3");

    // `one` also reads an external repository, which `two` does not: the external root differs.
    assertThat(one).isNotEqualTo(two);
    Spec twoAgain =
        build(
            b,
            ImmutableList.of(EXEC + "\\src\\other.c"),
            ImmutableList.of(EXEC + "\\bazel-out\\bin\\other.o"),
            TMP + "\\4");
    assertThat(two).isEqualTo(twoAgain);
    assertThat(three).isNotEqualTo(two);
  }

  @Test
  public void coarse_undeclaredTopLevelFileIsNotGranted() {
    Spec spec =
        build(
            builder(WindowsPsecPolicy.COARSE, true),
            ImmutableList.of(),
            ImmutableList.of(EXEC + "\\bazel-out\\bin\\neg\\out.txt"),
            TMP + "\\1");

    for (String p : spec.readOnly()) {
      assertThat(p.toLowerCase(Locale.ROOT)).doesNotContain("\\ws");
    }
    assertThat(spec.readOnly()).containsExactly("C:\\Kits", "C:\\VS");
  }

  @Test
  public void resolverResultsAreCached() {
    WindowsPsecPolicyBuilder b = builder(WindowsPsecPolicy.PRECISE, true);
    int before = resolverCalls.get();
    build(b, ImmutableList.of(EXEC + "\\src\\a.c"), ImmutableList.of(), TMP + "\\1");
    int afterFirst = resolverCalls.get();
    build(b, ImmutableList.of(EXEC + "\\src\\a.c"), ImmutableList.of(), TMP + "\\1");
    assertThat(afterFirst).isGreaterThan(before);
    assertThat(resolverCalls.get()).isEqualTo(afterFirst);
  }

  @Test
  public void pruneNested_isCaseInsensitiveAndRespectsSegmentBoundaries() {
    assertThat(
            WindowsPsecPolicyBuilder.pruneNested(
                ImmutableList.of("C:\\a\\b", "c:/A", "C:\\ab", "C:\\a\\", "C:\\x\\y")))
        .containsExactly("c:\\A", "C:\\ab", "C:\\x\\y")
        .inOrder();
    assertThat(WindowsPsecPolicyBuilder.parentOrNull("C:\\a")).isEqualTo("C:\\");
    assertThat(WindowsPsecPolicyBuilder.parentOrNull("C:\\")).isNull();
  }
}
