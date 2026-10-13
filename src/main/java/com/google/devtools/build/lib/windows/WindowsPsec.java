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

package com.google.devtools.build.lib.windows;

import com.google.devtools.build.lib.jni.JniLoader;
import java.io.IOException;
import java.util.List;
import javax.annotation.Nullable;

/**
 * Windows process security environments ("PSEC", {@code processmodel.dll}, Windows 11 25H2 build
 * 26200.9550 and later): a kernel-enforced, deny-by-default filesystem and network policy for a
 * whole process tree.
 *
 * <p>An environment is created once from a policy and can then be attached to any number of
 * processes, concurrently, with {@link WindowsProcesses#createProcessInSecurityEnvironment}.
 * Creating one costs about 30 ms plus about 1 ms per listed path (about 0.15 ms per path when the
 * filesystem policy is applied client side); attaching it to a process costs about 20 ms on top
 * of a normal process start.
 */
public final class WindowsPsec {

  /**
   * {@code JOB_OBJECT_UILIMIT_*} mask that keeps USER32 usable (tools such as cl.exe import it and
   * fail to start under the Win32k lockdown) while blocking the clipboard, desktop switching,
   * logoff, system settings, IME changes and input injection.
   */
  public static final long DESKTOP_UI_RESTRICTIONS = 0x3DE;

  static {
    JniLoader.loadJni();
  }

  private WindowsPsec() {}

  /** Returns null if process security environments can be used here, otherwise the reason. */
  @Nullable
  public static String checkSupport() {
    String error = nativeCheckSupport();
    return error.isEmpty() ? null : error;
  }

  /**
   * Creates a security environment. Paths are absolute Windows paths; a path listed with more than
   * one intent, or below a path with a weaker intent, gets the most restrictive one.
   *
   * @param readWrite paths the process tree may read and write
   * @param readOnly paths it may read
   * @param deny paths it may not access at all
   * @param enumerate directories it may list and traverse, but not read files in
   * @param disallowWin32k whether to block Win32k system calls (USER32 importers then fail)
   * @param uiRestrictions {@code JOB_OBJECT_UILIMIT_*} mask
   * @param allowNetwork whether outgoing network connections are allowed
   * @param clientFs whether to apply the filesystem policy from this process (directly to the
   *     bfs.sys filter driver) instead of through the AppInfo service; same enforcement, faster
   * @return the environment handle, to be released with {@link #closeEnvironment}
   */
  public static long createEnvironment(
      List<String> readWrite,
      List<String> readOnly,
      List<String> deny,
      List<String> enumerate,
      boolean disallowWin32k,
      long uiRestrictions,
      boolean allowNetwork,
      boolean clientFs)
      throws IOException {
    String[] error = new String[1];
    long handle =
        nativeCreateEnvironment(
            readWrite.toArray(new String[0]),
            readOnly.toArray(new String[0]),
            deny.toArray(new String[0]),
            enumerate.toArray(new String[0]),
            disallowWin32k,
            uiRestrictions,
            allowNetwork,
            clientFs,
            error);
    if (handle == 0) {
      throw new IOException(
          error[0] != null ? error[0] : "CreateProcessSecurityEnvironment failed");
    }
    return handle;
  }

  /**
   * Releases an environment. Must not be called while a process is being created in it; processes
   * already running in it stay confined.
   */
  public static void closeEnvironment(long handle) {
    nativeCloseEnvironment(handle);
  }

  /**
   * Resolves every path to its final target ({@code GetFinalPathNameByHandleW}, following
   * symlinks and junctions). An element of the result is null if the path does not exist or
   * resolves to a UNC path.
   */
  public static String[] getFinalPaths(String[] paths) {
    return nativeGetFinalPaths(paths);
  }

  private static native String nativeCheckSupport();

  private static native long nativeCreateEnvironment(
      String[] readWrite,
      String[] readOnly,
      String[] deny,
      String[] enumerate,
      boolean disallowWin32k,
      long uiRestrictions,
      boolean allowNetwork,
      boolean clientFs,
      String[] errorHolder);

  private static native void nativeCloseEnvironment(long handle);

  private static native String[] nativeGetFinalPaths(String[] paths);
}
