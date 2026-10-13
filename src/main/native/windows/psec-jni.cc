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

// JNI bindings for com.google.devtools.build.lib.windows.WindowsPsec.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>

#include <string>
#include <vector>

#include "src/main/native/jni.h"
#include "src/main/native/windows/file.h"
#include "src/main/native/windows/jni-util.h"
#include "src/main/native/windows/psec.h"

namespace {

std::string ToUtf8(const std::wstring& w) {
  if (w.empty()) return std::string();
  int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()),
                              nullptr, 0, nullptr, nullptr);
  std::string s(n, '\0');
  WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), &s[0],
                      n, nullptr, nullptr);
  return s;
}

std::vector<std::string> GetStrings(JNIEnv* env, jobjectArray array) {
  std::vector<std::string> result;
  if (array == nullptr) return result;
  jsize n = env->GetArrayLength(array);
  result.reserve(n);
  for (jsize i = 0; i < n; ++i) {
    jstring s = static_cast<jstring>(env->GetObjectArrayElement(array, i));
    result.push_back(ToUtf8(bazel::windows::GetJavaWstring(env, s)));
    env->DeleteLocalRef(s);
  }
  return result;
}

jstring NewJavaString(JNIEnv* env, const std::wstring& s) {
  return env->NewString(reinterpret_cast<const jchar*>(s.c_str()), s.size());
}

// The final (symlink- and junction-resolved) path of `path`, without the
// `\\?\` prefix. Empty if the path does not exist or resolves to a UNC path.
std::wstring FinalPath(const std::wstring& path) {
  std::wstring opened = bazel::windows::AddUncPrefixMaybe(path);
  HANDLE h = CreateFileW(opened.c_str(), FILE_READ_ATTRIBUTES,
                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                         nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS,
                         nullptr);
  if (h == INVALID_HANDLE_VALUE) return std::wstring();
  WCHAR stack_buf[MAX_PATH];
  std::wstring result;
  DWORD n = GetFinalPathNameByHandleW(h, stack_buf, MAX_PATH,
                                      FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
  if (n > 0 && n < MAX_PATH) {
    result.assign(stack_buf, n);
  } else if (n >= MAX_PATH) {
    std::vector<WCHAR> heap_buf(n + 1);
    n = GetFinalPathNameByHandleW(h, heap_buf.data(), n + 1,
                                  FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (n > 0 && n <= heap_buf.size()) result.assign(heap_buf.data(), n);
  }
  CloseHandle(h);
  if (result.compare(0, 8, L"\\\\?\\UNC\\") == 0) return std::wstring();
  if (result.compare(0, 4, L"\\\\?\\") == 0) result.erase(0, 4);
  return result;
}

}  // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_google_devtools_build_lib_windows_WindowsPsec_nativeCheckSupport(
    JNIEnv* env, jclass clazz) {
  return NewJavaString(env, bazel::windows::psec::EnsureLoaded());
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_google_devtools_build_lib_windows_WindowsPsec_nativeCreateEnvironment(
    JNIEnv* env, jclass clazz, jobjectArray read_write, jobjectArray read_only,
    jobjectArray deny, jobjectArray enumerate, jboolean disallow_win32k,
    jlong ui_restrictions, jboolean allow_network, jboolean client_fs,
    jobjectArray error_msg_holder) {
  bazel::windows::psec::Spec spec;
  spec.read_write = GetStrings(env, read_write);
  spec.read_only = GetStrings(env, read_only);
  spec.deny = GetStrings(env, deny);
  spec.enumerate = GetStrings(env, enumerate);
  spec.disallow_win32k_system_calls = disallow_win32k;
  spec.ui_restrictions = static_cast<uint64_t>(ui_restrictions);
  spec.allow_network = allow_network;
  std::wstring error;
  HANDLE result = bazel::windows::psec::CreateEnvironment(
      spec,
      client_fs ? bazel::windows::psec::FsApply::kClient
                : bazel::windows::psec::FsApply::kService,
      &error);
  if (result == nullptr && error_msg_holder != nullptr &&
      env->GetArrayLength(error_msg_holder) > 0) {
    env->SetObjectArrayElement(error_msg_holder, 0, NewJavaString(env, error));
  }
  return reinterpret_cast<jlong>(result);
}

extern "C" JNIEXPORT void JNICALL
Java_com_google_devtools_build_lib_windows_WindowsPsec_nativeCloseEnvironment(
    JNIEnv* env, jclass clazz, jlong handle) {
  bazel::windows::psec::CloseEnvironment(reinterpret_cast<HANDLE>(handle));
}

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_google_devtools_build_lib_windows_WindowsPsec_nativeGetFinalPaths(
    JNIEnv* env, jclass clazz, jobjectArray paths) {
  jsize n = env->GetArrayLength(paths);
  jobjectArray result =
      env->NewObjectArray(n, env->FindClass("java/lang/String"), nullptr);
  for (jsize i = 0; i < n; ++i) {
    jstring p = static_cast<jstring>(env->GetObjectArrayElement(paths, i));
    std::wstring final_path =
        FinalPath(bazel::windows::GetJavaWpath(env, p));
    env->DeleteLocalRef(p);
    if (!final_path.empty()) {
      jstring s = NewJavaString(env, final_path);
      env->SetObjectArrayElement(result, i, s);
      env->DeleteLocalRef(s);
    }
  }
  return result;
}
