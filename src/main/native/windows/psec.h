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

// Windows process security environments ("PSEC"): the kernel-enforced,
// deny-by-default filesystem/network policy that processmodel.dll implements
// on Windows 11 25H2 (build 26200.9550 and later for contract 1.1).
//
// The API is not declared in any SDK header yet; the signatures below come
// from Microsoft's MXC SDK FFI and the processmodel.pdb symbols. Everything is
// resolved at runtime, so this code loads and fails cleanly on older Windows.
//
// One environment (one HANDLE) carries a whole policy and can be attached to
// any number of CreateProcessW calls through the
// PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT attribute; the whole process tree
// started that way is confined by it.

#ifndef BAZEL_SRC_MAIN_NATIVE_WINDOWS_PSEC_H_
#define BAZEL_SRC_MAIN_NATIVE_WINDOWS_PSEC_H_

#include <stdint.h>

#include <string>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace bazel {
namespace windows {
namespace psec {

// ProcThreadAttributeSecurityEnvironment (35) | PROC_THREAD_ATTRIBUTE_INPUT.
// Not in WinBase.h as of SDK 10.0.26100.
constexpr uintptr_t kProcThreadAttributeSecurityEnvironment = 35 | 0x00020000;

// JOB_OBJECT_UILIMIT_* mask that keeps USER32 usable (no Win32k lockdown, no
// handle/atom isolation) while still blocking clipboard, desktop switching,
// logoff, system settings, IME and input injection. This is what MXC computes
// for `ui.isolation = desktop` with every other UI knob at its default.
constexpr uint64_t kDesktopUiRestrictions = 0x3DE;

// A policy. Paths are UTF-8, absolute, Windows-style.
struct Spec {
  std::vector<std::string> read_write;
  std::vector<std::string> read_only;
  std::vector<std::string> deny;
  // Directories that may be listed and traversed but not read (PSEC 1.1).
  std::vector<std::string> enumerate;
  bool disallow_win32k_system_calls = false;
  uint64_t ui_restrictions = kDesktopUiRestrictions;
  bool allow_network = false;
};

// Serializes `spec` into the "PSEC" FlatBuffer (schema
// ProcessSecurityEnvironment.fbs, version `major`.`minor`). `fs_enumerate` is
// only written for minor >= 1 and the ingress table only if `with_ingress`
// (QueryProcessSecurityEnvironmentSupport bit 0x8). Portable code, no Windows
// dependency, so it can be checked against the flatc reader anywhere.
std::vector<uint8_t> EncodeSpec(const Spec& spec, uint16_t major,
                                uint16_t minor, bool with_ingress);

#ifdef _WIN32

// Resolves the processmodel.dll exports and checks that contract 1.1 is
// available. Thread-safe; the work is done once. Returns an empty string on
// success, otherwise why PSEC cannot be used on this machine.
std::wstring EnsureLoaded();

// How the filesystem part of a policy reaches the kernel.
enum class FsApply {
  // In the spec: the AppInfo service applies every path, sequentially, at
  // about 1 ms per path (a GetVolumePathNameW walk over every ancestor plus a
  // file-backed policy-store write, microsoft/mxc#1468).
  kService,
  // Client side: the spec carries no paths, so the service skips its
  // per-path loops, and this process sends the same bfs.sys policy requests
  // itself (about 0.1 ms per path, in-memory policy store when available).
  kClient,
};

// What creating an environment did, for diagnostics.
struct CreateStats {
  // Client side only: policies sent to bfs.sys, paths skipped because they do
  // not exist, whether bfs.sys keeps them in memory, and the time spent
  // getting the token and applying the paths.
  uint32_t applied = 0;
  uint32_t missing = 0;
  bool in_memory = false;
  double token_ms = 0;
  double apply_ms = 0;
};

// Creates a security environment for `spec`. On failure returns nullptr and
// sets `error`. `stats` may be null.
HANDLE CreateEnvironment(const Spec& spec, FsApply fs, std::wstring* error,
                         CreateStats* stats = nullptr);

// The three steps of FsApply::kClient, separately, so that environments can
// be created ahead of time and reused for another policy:
//
// Creates an environment with `spec`'s network and UI settings and no
// filesystem access at all; its paths are ignored.
HANDLE CreateBlankEnvironment(const Spec& spec, std::wstring* error,
                              CreateStats* stats = nullptr);
// Adds `spec`'s paths to the filesystem policy of a blank environment.
bool ApplyFilesystem(HANDLE env, const Spec& spec, std::wstring* error,
                     CreateStats* stats = nullptr);
// Removes every path from the policy of such an environment again. No
// process may run in it.
bool ClearFilesystem(HANDLE env, std::wstring* error);

// Releases an environment. Processes already started in it keep running and
// stay confined; the handle must not be used for new processes afterwards.
// For a kClient environment no process may still run in it: its filesystem
// policy is removed too.
void CloseEnvironment(HANDLE env);

#endif  // _WIN32

}  // namespace psec
}  // namespace windows
}  // namespace bazel

#endif  // BAZEL_SRC_MAIN_NATIVE_WINDOWS_PSEC_H_
