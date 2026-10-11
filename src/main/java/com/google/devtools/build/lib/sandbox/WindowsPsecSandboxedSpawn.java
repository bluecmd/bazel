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

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.devtools.build.lib.shell.SubprocessFactory;
import com.google.devtools.build.lib.shell.WindowsSubprocessFactory;
import com.google.devtools.build.lib.vfs.Path;
import java.io.IOException;
import javax.annotation.Nullable;

/**
 * An action run in the execroot itself, confined by a Windows process security environment that
 * is attached to its process at creation.
 */
final class WindowsPsecSandboxedSpawn implements SandboxedSpawn {

  private final Path execRoot;
  private final ImmutableMap<String, String> environment;
  private final ImmutableList<String> arguments;
  private final String mnemonic;
  private final Path tmpDir;
  private final WindowsPsecEnvironmentPool.Lease lease;

  WindowsPsecSandboxedSpawn(
      Path execRoot,
      ImmutableMap<String, String> environment,
      ImmutableList<String> arguments,
      String mnemonic,
      Path tmpDir,
      WindowsPsecEnvironmentPool.Lease lease) {
    this.execRoot = execRoot;
    this.environment = environment;
    this.arguments = arguments;
    this.mnemonic = mnemonic;
    this.tmpDir = tmpDir;
    this.lease = lease;
  }

  @Override
  public Path getSandboxExecRoot() {
    return execRoot;
  }

  @Override
  public ImmutableList<String> getArguments() {
    return arguments;
  }

  @Override
  public ImmutableMap<String, String> getEnvironment() {
    return environment;
  }

  @Override
  public String getMnemonic() {
    return mnemonic;
  }

  @Override
  public SubprocessFactory getSubprocessFactory() {
    return WindowsSubprocessFactory.inSecurityEnvironment(lease.handle());
  }

  @Override
  public boolean useSubprocessTimeout() {
    // The process is ours, not a helper's, so the subprocess kills its job on timeout.
    return true;
  }

  @Override
  @Nullable
  public Path getSandboxDebugPath() {
    return null;
  }

  @Override
  @Nullable
  public Path getStatisticsPath() {
    return null;
  }

  @Override
  public void createFileSystem() {}

  @Override
  public void copyOutputs(Path execRoot) {}

  @Override
  public void delete() {
    lease.release();
    try {
      tmpDir.deleteTree();
    } catch (IOException e) {
      // Best effort; the runner's directory is removed at the end of the command.
    }
  }
}
