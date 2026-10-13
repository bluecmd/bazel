// Harness for psec::FsApply::kClient. Not part of Bazel.
//   clientfs_bench enforce <dir>             same checks under service and client mode
//   clientfs_bench create <dir> <n> <reps>   create(+first launch) time, n file grants
#include <windows.h>
#include <psapi.h>

#include <atomic>
#include <map>
#include <algorithm>
#include <mutex>
#include <chrono>
#include <cstdio>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "src/main/native/windows/process.h"
#include "src/main/native/windows/psec.h"

using namespace bazel::windows;
using Clock = std::chrono::steady_clock;
static double Ms(Clock::time_point t) {
  return std::chrono::duration<double, std::milli>(Clock::now() - t).count();
}
static std::string U8(const std::wstring& w) {
  int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, 0, 0, 0, 0);
  std::string s(n, 0);
  WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, &s[0], n, 0, 0);
  s.resize(n - 1);
  return s;
}

static int Run(const std::wstring& rest, const std::wstring& cwd, HANDLE env,
               const std::wstring& out_file, std::wstring* err) {
  WaitableProcess p;
  SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
  HANDLE nul = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_WRITE | FILE_SHARE_READ, &sa,
                           OPEN_EXISTING, 0, nullptr);
  HANDLE out = CreateFileW(out_file.empty() ? L"NUL" : out_file.c_str(), GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, &sa,
                           out_file.empty() ? OPEN_EXISTING : CREATE_ALWAYS, 0, nullptr);
  HANDLE dup;
  DuplicateHandle(GetCurrentProcess(), out, GetCurrentProcess(), &dup, 0, TRUE,
                  DUPLICATE_SAME_ACCESS);
  bool ok = p.Create(L"C:\\Windows\\System32\\cmd.exe", rest, nullptr, cwd, nul, out, dup,
                     nullptr, err, env);
  CloseHandle(nul);
  CloseHandle(out);
  CloseHandle(dup);
  if (!ok) return -1000;
  p.WaitFor(-1, nullptr, err);
  return p.GetExitCode(err);
}

static void AddAncestors(const std::string& p, std::set<std::string>* out) {
  std::string a = p;
  while (true) {
    size_t k = a.find_last_of('\\');
    if (k == std::string::npos) break;
    a = a.substr(0, k);
    if (a.size() <= 2) { out->insert(a + "\\"); break; }
    out->insert(a);
  }
}

static psec::Spec SpecFor(const std::wstring& dir, int synth) {
  psec::Spec s;
  std::string d = U8(dir);
  s.read_only = {d + "\\in"};
  s.read_write = {d + "\\out"};
  s.deny = {d + "\\in\\denied.txt", d + "\\in\\missing-denied"};
  for (int i = 0; i < synth; i++) {
    char b[256];
    sprintf(b, "%s\\synth\\d%03d\\f%05d.txt", d.c_str(), i / 100, i);
    s.read_only.push_back(b);
  }
  std::set<std::string> anc;
  AddAncestors(d + "\\x", &anc);
  for (auto& r : s.read_only) AddAncestors(r, &anc);
  anc.erase(d + "\\in");
  s.enumerate.assign(anc.begin(), anc.end());
  return s;
}

static void MakeSynth(const std::wstring& dir, int n) {
  CreateDirectoryW((dir + L"\\synth").c_str(), nullptr);
  for (int i = 0; i < n; i++) {
    wchar_t b[512];
    swprintf(b, 512, L"%s\\synth\\d%03d", dir.c_str(), i / 100);
    CreateDirectoryW(b, nullptr);
    swprintf(b, 512, L"%s\\synth\\d%03d\\f%05d.txt", dir.c_str(), i / 100, i);
    HANDLE h = CreateFileW(b, GENERIC_WRITE, 0, nullptr, CREATE_NEW, 0, nullptr);
    if (h != INVALID_HANDLE_VALUE) { DWORD w; WriteFile(h, "x", 1, &w, nullptr); CloseHandle(h); }
  }
}

static void PrintStats(const char* what, const psec::CreateStats& st) {
  printf("  %s: applied=%u missing=%u in_memory=%d token=%.1f ms apply=%.1f ms\n", what,
         st.applied, st.missing, (int)st.in_memory, st.token_ms, st.apply_ms);
}

static std::string Slurp(const std::wstring& f) {
  std::string s;
  FILE* fp = _wfopen(f.c_str(), L"rb");
  if (!fp) return "<no file>";
  char b[4096];
  size_t n;
  while ((n = fread(b, 1, sizeof b, fp)) > 0) s.append(b, n);
  fclose(fp);
  return s;
}

static void BfsPool(long long* s, long long* g) {
  std::vector<char> buf(1 << 20);
  ULONG len = 0;
  typedef LONG(NTAPI * Q)(ULONG, void*, ULONG, ULONG*);
  static Q q = (Q)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
  while (q(22, buf.data(), (ULONG)buf.size(), &len) == (LONG)0xC0000004) buf.resize(buf.size() * 2);
  struct T { char tag[4]; ULONG pa, pf; SIZE_T pu; ULONG na, nf; SIZE_T nu; };
  ULONG count = *(ULONG*)buf.data();
  T* t = (T*)(buf.data() + sizeof(void*));
  *s = *g = 0;
  for (ULONG i = 0; i < count; i++) {
    if (!memcmp(t[i].tag, "BfsS", 4)) *s = (long long)t[i].pa - t[i].pf;
    if (!memcmp(t[i].tag, "BfsG", 4)) *g = (long long)t[i].pa - t[i].pf;
  }
}

// All pool tags: tag -> outstanding allocations (paged + nonpaged).
static std::map<std::string, long long> PoolTags() {
  std::vector<char> buf(1 << 20);
  ULONG len = 0;
  typedef LONG(NTAPI * Q)(ULONG, void*, ULONG, ULONG*);
  static Q q = (Q)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
  while (q(22, buf.data(), (ULONG)buf.size(), &len) == (LONG)0xC0000004) buf.resize(buf.size() * 2);
  struct T { char tag[4]; ULONG pa, pf; SIZE_T pu; ULONG na, nf; SIZE_T nu; };
  ULONG count = *(ULONG*)buf.data();
  T* t = (T*)(buf.data() + sizeof(void*));
  std::map<std::string, long long> m;
  for (ULONG i = 0; i < count; i++)
    m[std::string(t[i].tag, 4)] = (long long)t[i].pa - t[i].pf + (long long)t[i].na - t[i].nf;
  return m;
}

int wmain(int argc, wchar_t** argv) {
  setvbuf(stdout, nullptr, _IONBF, 0);
  std::wstring e = psec::EnsureLoaded();
  if (!e.empty()) { wprintf(L"unsupported: %s\n", e.c_str()); return 2; }
  std::wstring mode = argv[1], dir = argv[2];
  if (mode == L"enforce") {
    for (auto fs : {psec::FsApply::kService, psec::FsApply::kClient}) {
      const char* name = fs == psec::FsApply::kService ? "service" : "client";
      std::wstring err;
      psec::CreateStats st;
      auto t = Clock::now();
      HANDLE env = psec::CreateEnvironment(SpecFor(dir, 0), fs, &err, &st);
      printf("== %s: create %.1f ms\n", name, Ms(t));
      if (!env) { printf("  create failed: %s\n", U8(err).c_str()); continue; }
      PrintStats(name, st);
      DeleteFileW((dir + L"\\leak.txt").c_str());
      // Four concurrent children: every check, each its own output file.
      std::vector<std::thread> th;
      std::vector<int> rc(4);
      for (int i = 0; i < 4; i++) {
        th.emplace_back([&, i] {
          std::wstring err2;
          wchar_t rest[2048];
          swprintf(rest, 2048,
                   L"/c (echo [read-in] & type %s\\in\\x.txt) & (echo [write-out] & echo ok> %s\\out\\w%d.txt && type %s\\out\\w%d.txt) & "
                   L"(echo [read-secret] & type %s\\secret.txt) & (echo [write-leak] & echo leak> %s\\leak.txt) & "
                   L"(echo [write-in] & echo x> %s\\in\\new.txt) & (echo [read-denied] & type %s\\in\\denied.txt) & "
                   L"(echo [mkdir-missing-denied] & mkdir %s\\in\\missing-denied) & (echo [list-dir] & dir /b %s) & (echo [cd-dir] & cd %s\\in & cd)",
                   dir.c_str(), dir.c_str(), i, dir.c_str(), i, dir.c_str(), dir.c_str(), dir.c_str(),
                   dir.c_str(), dir.c_str(), dir.c_str(), dir.c_str());
          wchar_t of[512];
          swprintf(of, 512, L"%s\\res-%S-%d.txt", dir.c_str(), name, i);
          rc[i] = Run(rest, dir, env, of, &err2);
          if (rc[i] == -1000) printf("spawn %d: %s\n", i, U8(err2).c_str());
        });
      }
      for (auto& t2 : th) t2.join();
      printf("  rcs: %d %d %d %d, leak.txt exists: %d\n", rc[0], rc[1], rc[2], rc[3],
             GetFileAttributesW((dir + L"\\leak.txt").c_str()) != INVALID_FILE_ATTRIBUTES);
      wchar_t of[512];
      swprintf(of, 512, L"%s\\res-%S-0.txt", dir.c_str(), name);
      printf("%s", Slurp(of).c_str());
      psec::CloseEnvironment(env);
    }
    return 0;
  }
  if (mode == L"recycle") {
    // blank -> policy A -> run -> clear -> policy B -> run -> clear -> run.
    std::string d = U8(dir);
    psec::Spec a = SpecFor(dir, 0);
    psec::Spec b;
    b.read_only = {d + "\\secret.txt"};
    b.read_write = {d + "\\out"};
    b.enumerate = a.enumerate;
    b.enumerate.push_back(d);
    std::wstring err;
    psec::CreateStats st;
    auto t = Clock::now();
    HANDLE env = psec::CreateBlankEnvironment(a, &err, &st);
    printf("blank create %.1f ms (token %.1f, in_memory %d) %s\n", Ms(t), st.token_ms, (int)st.in_memory, U8(err).c_str());
    if (!env) return 1;
    std::wstring checks = L"/c (echo [read-in] & type " + dir + L"\\in\\x.txt) & (echo [read-secret] & type " + dir +
                          L"\\secret.txt) & (echo [write-out] & echo ok> " + dir + L"\\out\\r.txt && type " + dir + L"\\out\\r.txt)";
    const char* phases[] = {"A", "B", "cleared"};
    for (int ph = 0; ph < 3; ph++) {
      t = Clock::now();
      bool ok = true;
      if (ph == 0) ok = psec::ApplyFilesystem(env, a, &err, &st);
      if (ph == 1) { ok = psec::ClearFilesystem(env, &err) && psec::ApplyFilesystem(env, b, &err, &st); }
      if (ph == 2) ok = psec::ClearFilesystem(env, &err);
      printf("== policy %s: %s %.1f ms\n", phases[ph], ok ? "ok" : U8(err).c_str(), Ms(t));
      wchar_t of[512];
      swprintf(of, 512, L"%s\\recycle-%d.txt", dir.c_str(), ph);
      int rc = Run(checks, L"C:\\Windows\\System32", env, of, &err);
      printf("rc=%d\n%s", rc, Slurp(of).c_str());
    }
    // Cost of a recycle vs a fresh blank environment.
    double clear = 0, fresh = 0;
    for (int i = 0; i < 20; i++) {
      t = Clock::now(); psec::ClearFilesystem(env, &err); psec::ApplyFilesystem(env, a, &err, &st); clear += Ms(t);
      t = Clock::now(); HANDLE e2 = psec::CreateBlankEnvironment(a, &err, &st); psec::ApplyFilesystem(e2, a, &err, &st); fresh += Ms(t);
      psec::CloseEnvironment(e2);
    }
    printf("mean of 20: clear+apply %.2f ms, blank create+apply %.2f ms\n", clear / 20, fresh / 20);
    psec::CloseEnvironment(env);
    return 0;
  }
  if (mode == L"stress") {
    // 16 threads, each with its own environment recycled 10 times between two
    // policies; every run must see exactly its current policy.
    std::string d = U8(dir);
    psec::Spec a = SpecFor(dir, 0);
    psec::Spec b;
    b.read_only = {d + "\\secret.txt"};
    b.read_write = {d + "\\out"};
    b.enumerate = a.enumerate;
    b.enumerate.push_back(d);
    std::atomic<int> bad{0}, runs{0};
    std::vector<std::thread> th;
    auto t0 = Clock::now();
    for (int i = 0; i < 16; i++) {
      th.emplace_back([&, i] {
        std::wstring err;
        HANDLE env = psec::CreateBlankEnvironment(a, &err);
        if (!env) { printf("blank %d: %s\n", i, U8(err).c_str()); bad++; return; }
        for (int k = 0; k < 10; k++) {
          bool useA = (k + i) % 2 == 0;
          if (!psec::ClearFilesystem(env, &err) || !psec::ApplyFilesystem(env, useA ? a : b, &err)) {
            printf("apply %d/%d: %s\n", i, k, U8(err).c_str()); bad++; continue;
          }
          wchar_t of[512];
          swprintf(of, 512, L"%s\\stress-%d.txt", dir.c_str(), i);
          std::wstring checks = L"/c (type " + dir + L"\\in\\x.txt & type " + dir + L"\\secret.txt) 2>&1";
          Run(checks, L"C:\\Windows\\System32", env, of, &err);
          std::string out = Slurp(of);
          bool sawIn = out.find("hello-in") != std::string::npos;
          bool sawSecret = out.find("secret-content") != std::string::npos;
          if (sawIn != useA || sawSecret != !useA) {
            printf("WRONG %d/%d policy %s: in=%d secret=%d\n", i, k, useA ? "A" : "B", sawIn, sawSecret);
            bad++;
          }
          runs++;
        }
        psec::CloseEnvironment(env);
      });
    }
    for (auto& t2 : th) t2.join();
    printf("stress: %d runs, %d bad, %.0f ms\n", runs.load(), bad.load(), Ms(t0));
    return 0;
  }
  if (mode == L"churn") {
    // churn <dir> <max> <launch>: create (client) + optional launch + close
    // until failure; every 1000 print the pool tags that grew most.
    int max = _wtoi(argv[3]), launch = _wtoi(argv[4]);
    bool service = argc > 5 && std::wstring(argv[5]) == L"service";
    int every = argc > 6 ? _wtoi(argv[6]) : 1000;
    psec::Spec sp = SpecFor(dir, 0);
    auto base = PoolTags();
    auto t0 = Clock::now();
    for (int i = 1; i <= max; i++) {
      std::wstring err;
      HANDLE env = psec::CreateEnvironment(sp, service ? psec::FsApply::kService : psec::FsApply::kClient, &err);
      if (!env) { printf("iter %d: create failed: %s\n", i, U8(err).c_str()); break; }
      if (launch) {
        int rc = Run(L"/c exit 0", L"C:\\Windows\\System32", env, L"", &err);
        if (rc != 0) { printf("iter %d: run rc=%d %s\n", i, rc, U8(err).c_str()); psec::CloseEnvironment(env); break; }
      }
      psec::CloseEnvironment(env);
      if (i % every == 0) {
        auto now = PoolTags();
        std::vector<std::pair<long long, std::string>> d;
        for (auto& kv : now) d.push_back({kv.second - base[kv.first], kv.first});
        std::sort(d.rbegin(), d.rend());
        printf("iter %d t=%.0fs grew:", i, Ms(t0) / 1000);
        for (int k = 0; k < 6; k++) printf(" %s+%lld", d[k].second.c_str(), d[k].first);
        printf("\n");
      }
    }
    return 0;
  }
  if (mode == L"bfsleak2") {
    // One environment: A, clear, A, clear, B (disjoint), close; then a second
    // environment with A. Prints outstanding BfsS+BfsG allocations after each.
    int n = _wtoi(argv[3]);
    MakeSynth(dir, 2 * n);
    psec::Spec a = SpecFor(dir, 0), b = SpecFor(dir, 0);
    std::string d = U8(dir);
    for (int i = 0; i < 2 * n; i++) {
      char p[256];
      sprintf(p, "%s\\synth\\d%03d\\f%05d.txt", d.c_str(), i / 100, i);
      (i < n ? a : b).read_only.push_back(p);
    }
    long long s0, g0, s, g;
    BfsPool(&s0, &g0);
    auto report = [&](const char* what) {
      Sleep(500);
      BfsPool(&s, &g);
      printf("%-28s outstanding +%lld\n", what, (s - s0) + (g - g0));
    };
    std::wstring err;
    HANDLE env = psec::CreateBlankEnvironment(a, &err);
    report("blank");
    psec::ApplyFilesystem(env, a, &err); report("apply A");
    psec::ClearFilesystem(env, &err); report("clear");
    psec::ApplyFilesystem(env, a, &err); report("apply A again");
    psec::ClearFilesystem(env, &err); report("clear");
    psec::ApplyFilesystem(env, b, &err); report("apply B (disjoint)");
    psec::CloseEnvironment(env); report("close");
    HANDLE env2 = psec::CreateBlankEnvironment(a, &err);
    psec::ApplyFilesystem(env2, a, &err); report("second env, apply A");
    psec::CloseEnvironment(env2); report("close second");
    return 0;
  }
  if (mode == L"bfsleak") {
    // bfsleak <dir> <n> <reps>: outstanding BfsS/BfsG pool allocations around
    // create+launch+close of an n-path environment, per mode, and recycling.
    int n = _wtoi(argv[3]), reps = _wtoi(argv[4]);
    MakeSynth(dir, n);
    psec::Spec sp = SpecFor(dir, n);
    auto pool = [](long long* s, long long* g, long long* sb, long long* gb) {
      std::vector<char> buf(1 << 20);
      ULONG len = 0;
      typedef LONG(NTAPI * Q)(ULONG, void*, ULONG, ULONG*);
      static Q q = (Q)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
      while (q(22, buf.data(), (ULONG)buf.size(), &len) == (LONG)0xC0000004) buf.resize(buf.size() * 2);
      struct T { char tag[4]; ULONG pa, pf; SIZE_T pu; ULONG na, nf; SIZE_T nu; };
      ULONG count = *(ULONG*)buf.data();
      T* t = (T*)(buf.data() + sizeof(void*));
      *s = *g = *sb = *gb = 0;
      for (ULONG i = 0; i < count; i++) {
        if (!memcmp(t[i].tag, "BfsS", 4)) { *s = (long long)t[i].pa - t[i].pf; *sb = t[i].pu; }
        if (!memcmp(t[i].tag, "BfsG", 4)) { *g = (long long)t[i].pa - t[i].pf; *gb = t[i].pu; }
      }
    };
    long long s0, g0, sb0, gb0, s1, g1, sb1, gb1;
    const char* names[] = {"service", "client", "recycle"};
    for (int m = 0; m < 3; m++) {
      pool(&s0, &g0, &sb0, &gb0);
      for (int r = 0; r < reps; r++) {
        std::wstring err;
        HANDLE env;
        if (m == 2) {
          env = psec::CreateBlankEnvironment(sp, &err);
          for (int k = 0; k < 5 && env; k++) { psec::ClearFilesystem(env, &err); psec::ApplyFilesystem(env, sp, &err); }
        } else {
          env = psec::CreateEnvironment(sp, m == 0 ? psec::FsApply::kService : psec::FsApply::kClient, &err);
        }
        if (!env) { printf("%s: %s\n", names[m], U8(err).c_str()); return 1; }
        Run(L"/c exit 0", L"C:\\Windows\\System32", env, L"", &err);
        psec::CloseEnvironment(env);
      }
      Sleep(2000);
      pool(&s1, &g1, &sb1, &gb1);
      int applies = m == 2 ? reps * 5 : reps;
      printf("%-8s %d x %d paths (%d applies): BfsS +%lld allocs +%lld KB, BfsG +%lld allocs +%lld KB, per path applied %.2f allocs\n",
             names[m], reps, (int)sp.read_only.size(), applies, s1 - s0, (sb1 - sb0) >> 10, g1 - g0, (gb1 - gb0) >> 10,
             double(s1 - s0 + g1 - g0) / (applies * (double)sp.read_only.size()));
    }
    return 0;
  }
  if (mode == L"storm") {
    // storm <dir> <threads> <seconds> <keep>: stock-like recycling under load.
    int threads = _wtoi(argv[3]), seconds = _wtoi(argv[4]), keep = _wtoi(argv[5]);
    MakeSynth(dir, 300);
    psec::Spec sp = SpecFor(dir, 300);
    wchar_t exe[1024] = L"", ro[4096] = L"";
    GetEnvironmentVariableW(L"MANY_EXE", exe, 1024);
    if (GetEnvironmentVariableW(L"MANY_RO", ro, 4096)) {
      std::string r = U8(ro);
      size_t st = 0;
      while (st < r.size()) {
        size_t k = r.find(';', st);
        if (k == std::string::npos) k = r.size();
        if (k > st) {
          sp.read_only.push_back(r.substr(st, k - st));
          std::set<std::string> anc;
          AddAncestors(r.substr(st, k - st), &anc);
          for (auto& a : anc) sp.enumerate.push_back(a);
        }
        st = k + 1;
      }
    }
    std::mutex mu;
    std::vector<HANDLE> stock;
    std::atomic<bool> stop{false};
    std::atomic<int> runs{0}, fails{0}, creates{0}, recycles{0};
    auto deadline = Clock::now() + std::chrono::seconds(seconds);
    auto create = [&](std::wstring* err) {
      HANDLE e = psec::CreateBlankEnvironment(sp, err);
      creates++;
      return e;
    };
    std::thread refiller([&] {
      while (!stop) {
        size_t n;
        { std::lock_guard<std::mutex> l(mu); n = stock.size(); }
        if (n >= (size_t)keep) { Sleep(5); continue; }
        std::wstring err;
        HANDLE e = create(&err);
        if (!e) { printf("refill: %s\n", U8(err).c_str()); fails++; Sleep(100); continue; }
        std::lock_guard<std::mutex> l(mu);
        stock.push_back(e);
      }
    });
    std::vector<std::thread> th;
    for (int i = 0; i < threads; i++) {
      th.emplace_back([&, i] {
        while (Clock::now() < deadline) {
          std::wstring err;
          HANDLE env = nullptr;
          { std::lock_guard<std::mutex> l(mu); if (!stock.empty()) { env = stock.back(); stock.pop_back(); } }
          if (env == nullptr) {
            env = create(&err);
            if (!env) { printf("inline create: %s\n", U8(err).c_str()); fails++; continue; }
          } else {
            psec::ClearFilesystem(env, &err);
            recycles++;
          }
          if (!psec::ApplyFilesystem(env, sp, &err)) { printf("apply: %s\n", U8(err).c_str()); fails++; }
          std::wstring c2 = exe[0] ? L"/c \"" + std::wstring(exe) + L"\" >NUL 2>&1" : L"/c exit 0";
          int rc = Run(c2, L"C:\\Windows\\System32", env, L"", &err);
          if (rc == -1000 || (rc != 0 && rc != 2)) { printf("run rc=%d: %s\n", rc, U8(err).c_str()); fails++; }
          runs++;
          bool kept = false;
          { std::lock_guard<std::mutex> l(mu); if (stock.size() < (size_t)keep * 2) { stock.push_back(env); kept = true; } }
          if (!kept) psec::CloseEnvironment(env);
        }
      });
    }
    for (auto& t : th) t.join();
    stop = true;
    refiller.join();
    for (HANDLE e : stock) psec::CloseEnvironment(e);
    printf("storm: runs=%d fails=%d creates=%d recycles=%d\n", runs.load(), fails.load(), creates.load(), recycles.load());
    return 0;
  }
  if (mode == L"many") {
    // many <dir> <max>: open blank environments without closing them; launch
    // cmd in each; stop at the first failure.
    int max = _wtoi(argv[3]);
    psec::Spec sp = SpecFor(dir, 0);
    // Optional: a USER32-importing tool and the roots it needs.
    wchar_t exe[1024] = L"", ro[4096] = L"";
    GetEnvironmentVariableW(L"MANY_EXE", exe, 1024);
    if (GetEnvironmentVariableW(L"MANY_RO", ro, 4096)) {
      std::string r = U8(ro);
      size_t st = 0;
      while (st < r.size()) {
        size_t k = r.find(';', st);
        if (k == std::string::npos) k = r.size();
        if (k > st) {
          sp.read_only.push_back(r.substr(st, k - st));
          std::set<std::string> anc;
          AddAncestors(r.substr(st, k - st), &anc);
          for (auto& a : anc) sp.enumerate.push_back(a);
        }
        st = k + 1;
      }
    }
    std::wstring cmd = exe[0] ? L"/c \"\"" + std::wstring(exe) + L"\" /? >NUL 2>&1 & exit 0\"" : L"/c exit 0";
    std::vector<HANDLE> envs;
    for (int i = 0; i < max; i++) {
      std::wstring err;
      HANDLE env = psec::CreateBlankEnvironment(sp, &err);
      if (!env) { printf("env %d: create failed: %s\n", i, U8(err).c_str()); break; }
      envs.push_back(env);
      psec::ApplyFilesystem(env, sp, &err);
      wchar_t of[512];
      swprintf(of, 512, L"%s\\many.txt", dir.c_str());
      std::wstring c2 = exe[0] ? L"/c \"" + std::wstring(exe) + L"\" 2>&1 & echo rc=!errorlevel!" : L"/c echo rc=0";
      int rc = Run(L"/v:on " + c2, L"C:\\Windows\\System32", env, of, &err);
      std::string out = Slurp(of);
      if (rc != 0 || out.find("rc=0") == std::string::npos && out.find("Usage") == std::string::npos && out.find("usage") == std::string::npos) {
        printf("env %d: run rc=%d %s\n%s\n", i, rc, U8(err).c_str(), out.c_str()); break; }
      if (i == 0) printf("first output:\n%s\n", out.c_str());
      if (i % 10 == 0) printf("env %d ok\n", i);
    }
    printf("open: %zu\n", envs.size());
    for (HANDLE e : envs) psec::CloseEnvironment(e);
    return 0;
  }
  if (mode == L"leak") {
    // leak <dir> <iterations> <paths> <launch 0/1>: one environment, cleared and
    // re-applied over and over; every 100 iterations print kernel pool usage.
    int iters = _wtoi(argv[3]), n = _wtoi(argv[4]), launch = _wtoi(argv[5]);
    MakeSynth(dir, n);
    psec::Spec sp = SpecFor(dir, n);
    std::wstring err;
    HANDLE env = psec::CreateBlankEnvironment(sp, &err);
    if (!env) { printf("blank: %s\n", U8(err).c_str()); return 1; }
    auto t0 = Clock::now();
    for (int i = 0; i <= iters; i++) {
      if (!psec::ClearFilesystem(env, &err) || !psec::ApplyFilesystem(env, sp, &err)) {
        printf("iter %d: %s\n", i, U8(err).c_str()); return 1;
      }
      if (launch) {
        int rc = Run(L"/c exit 0", L"C:\\Windows\\System32", env, L"", &err);
        if (rc != 0) { printf("iter %d run rc=%d %s\n", i, rc, U8(err).c_str()); return 1; }
      }
      if (i % 100 == 0) {
        PERFORMANCE_INFORMATION pi{};
        pi.cb = sizeof(pi);
        GetPerformanceInfo(&pi, sizeof(pi));
        printf("iter %5d t=%6.1fs paged=%7zu MB nonpaged=%5zu MB handles=%lu\n", i, Ms(t0) / 1000,
               pi.KernelPaged * pi.PageSize >> 20, pi.KernelNonpaged * pi.PageSize >> 20, pi.HandleCount);
      }
    }
    psec::CloseEnvironment(env);
    PERFORMANCE_INFORMATION pi{};
    pi.cb = sizeof(pi);
    GetPerformanceInfo(&pi, sizeof(pi));
    printf("closed: paged=%zu MB nonpaged=%zu MB\n", pi.KernelPaged * pi.PageSize >> 20, pi.KernelNonpaged * pi.PageSize >> 20);
    return 0;
  }
  if (mode == L"attrs") {
    // Cost of the GetFileAttributesExW part of apply alone, n synth paths.
    int n = _wtoi(argv[3]);
    MakeSynth(dir, n);
    psec::Spec sp = SpecFor(dir, n);
    for (int r = 0; r < 4; r++) {
      auto t = Clock::now();
      for (auto& p : sp.read_only) {
        std::wstring w(p.begin(), p.end());
        WIN32_FILE_ATTRIBUTE_DATA d;
        GetFileAttributesExW(w.c_str(), GetFileExInfoStandard, &d);
      }
      printf("attrs n=%zu: %.1f ms\n", sp.read_only.size(), Ms(t));
    }
    return 0;
  }
  if (mode == L"create") {
    int n = _wtoi(argv[3]), reps = _wtoi(argv[4]);
    MakeSynth(dir, n);
    for (int r = 0; r <= reps; r++) {
      for (auto fs : {psec::FsApply::kService, psec::FsApply::kClient}) {
        const char* name = fs == psec::FsApply::kService ? "service" : "client";
        std::wstring err;
        psec::CreateStats st;
        auto t = Clock::now();
        HANDLE env = psec::CreateEnvironment(SpecFor(dir, n), fs, &err, &st);
        double c = Ms(t);
        if (!env) { printf("%s create failed: %s\n", name, U8(err).c_str()); continue; }
        wchar_t rest[512];
        swprintf(rest, 512, L"/c type %s\\synth\\d000\\f00000.txt", dir.c_str());
        int rc = n > 0 ? Run(rest, dir, env, L"", &err) : Run(L"/c exit 0", dir, env, L"", &err);
        double total = Ms(t);
        psec::CloseEnvironment(env);
        printf("n=%d rep=%d %-7s create=%7.1f ms (token %.1f, apply %.1f, applied %u, missing %u, in_memory %d) +launch=%7.1f ms rc=%d\n",
               n, r, name, c, st.token_ms, st.apply_ms, st.applied, st.missing, (int)st.in_memory,
               total, rc);
      }
    }
    return 0;
  }
  return 2;
}
