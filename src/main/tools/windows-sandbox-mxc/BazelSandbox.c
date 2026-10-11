/* BazelSandbox.exe: adapter between Bazel's windows-sandbox spawn runner
 * (WindowsSandboxUtil.java) and Microsoft Execution Containers' wxc-exec.exe.
 *
 *   BazelSandbox [-W <cwd>] [-T <timeout s>] [-t <kill delay s>] [-l <stdout>]
 *                [-L <stderr>] (-w <rw path>)* (-r <ro path>)* (-b <denied path>)*
 *                [-D] -- <argv...>
 *
 * Writes a schema-1.0.0 "processcontainer" request to %TEMP% and runs
 *   wxc-exec.exe <request.json>
 * with stdout/stderr redirected to -l/-L when given. Exit code is wxc-exec's,
 * i.e. the action's. The current process environment (Bazel's scrubbed action
 * environment) is handed to the container verbatim.
 *
 * Environment knobs (reach the adapter through --action_env):
 *   BAZEL_MXC_EXTRA_RO=<p>;<p>  extra read-only roots: toolchains Bazel does not
 *                               declare as inputs (MSVC, Windows Kits, node, ...)
 *   BAZEL_MXC_ENUM_CWD=1        list the cwd (execroot) as enumerate-only when no
 *                               grant covers it
 *   BAZEL_MXC_ENUM_ANCESTORS=1  list every ancestor of every grant and of the cwd
 *                               as enumerate-only (needed for dir, exe launch,
 *                               realpath; requires PSEC 1.1 / 26200.9550+)
 *   BAZEL_MXC_UI=1              ui.disable=false + ui.isolation=desktop, without
 *                               which anything importing USER32 dies with
 *                               STATUS_DLL_INIT_FAILED
 *   BAZEL_MXC_WXC=<path>        wxc-exec.exe location (default: next to this exe)
 *   BAZEL_MXC_KEEP=1            keep the request file and print its path to stderr
 *
 * See README.md next to this file for what works and what does not.
 */
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <shlobj.h>
#pragma comment(lib, "shell32.lib")
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAXP 65536
static const char *ro[MAXP], *rw[MAXP], *deny[MAXP];
static int nro, nrw, ndeny;

static void jstr(FILE *f, const char *s) {
    fputc('"', f);
    for (; *s; s++) {
        if (*s == '"' || *s == '\\') { fputc('\\', f); fputc(*s, f); }
        else if ((unsigned char)*s < 0x20) fprintf(f, "\\u%04x", (unsigned char)*s);
        else fputc(*s, f);
    }
    fputc('"', f);
}
static void jlist(FILE *f, const char *key, const char **v, int n) {
    fprintf(f, "%s: [", key);
    for (int i = 0; i < n; i++) { if (i) fputs(", ", f); jstr(f, v[i]); }
    fputs("]", f);
}

/* Case-insensitive path prefix test treating '/' and '\\' alike. */
static int path_eq_n(const char *a, const char *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        char x = a[i], y = b[i];
        if (x == '/') x = '\\'; if (y == '/') y = '\\';
        if (tolower((unsigned char)x) != tolower((unsigned char)y)) return 0;
    }
    return 1;
}
static int path_listed(const char **v, int n, const char *p) {
    size_t lp = strlen(p);
    for (int i = 0; i < n; i++) if (strlen(v[i]) == lp && path_eq_n(v[i], p, lp)) return 1;
    return 0;
}
/* True when some ro/rw grant equals p or is a directory above p (MXC applies
 * the most restrictive intent to a path listed twice, so never enumerate a
 * granted path). */
static int path_covered(const char *p) {
    size_t lp = strlen(p);
    for (int k = 0; k < nro + nrw; k++) {
        const char *g = k < nro ? ro[k] : rw[k - nro];
        size_t lg = strlen(g);
        while (lg > 3 && (g[lg - 1] == '\\' || g[lg - 1] == '/')) lg--;
        if (lg == lp && path_eq_n(g, p, lp)) return 1;
        if (lg < lp && path_eq_n(g, p, lg) && (p[lg] == '\\' || p[lg] == '/')) return 1;
    }
    return 0;
}
/* argv -> Windows command line, per the CRT's parsing rules */
static void quote_arg(char *out, size_t cap, const char *a) {
    size_t o = strlen(out);
    int need = (*a == 0) || strpbrk(a, " \t\"") != NULL;
    if (!need) { strncat(out, a, cap - o - 1); return; }
    out[o++] = '"';
    for (const char *p = a; ; p++) {
        int bs = 0;
        while (*p == '\\') { bs++; p++; }
        if (*p == 0) { for (int i = 0; i < bs * 2; i++) out[o++] = '\\'; break; }
        if (*p == '"') { for (int i = 0; i < bs * 2 + 1; i++) out[o++] = '\\'; out[o++] = '"'; }
        else { for (int i = 0; i < bs; i++) out[o++] = '\\'; out[o++] = *p; }
        if (o + 4 >= cap) break;
    }
    out[o++] = '"'; out[o] = 0;
}
/* Bazel's execroot is a forest of symlinks/junctions into the source tree
 * and MXC evaluates its policy on the resolved target, so grant that too. */
static void add_targets(const char **v, int *n) {
    int orig = *n;
    for (int i = 0; i < orig && *n < MAXP; i++) {
        HANDLE h = CreateFileA(v[i], 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                               OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
        if (h == INVALID_HANDLE_VALUE) continue;
        char buf[4096];
        DWORD len = GetFinalPathNameByHandleA(h, buf, sizeof buf, FILE_NAME_NORMALIZED);
        CloseHandle(h);
        if (len == 0 || len >= sizeof buf) continue;
        const char *r = buf;
        if (!strncmp(r, "\\\\?\\UNC\\", 8)) continue;
        if (!strncmp(r, "\\\\?\\", 4)) r += 4;
        /* compare ignoring case and slash direction */
        const char *a = v[i], *b = r; int same = 1;
        for (; *a && *b; a++, b++) {
            char ca = (*a == '/') ? '\\' : *a, cb = (*b == '/') ? '\\' : *b;
            if (tolower((unsigned char)ca) != tolower((unsigned char)cb)) { same = 0; break; }
        }
        if (same && *a == 0 && *b == 0) continue;
        v[(*n)++] = _strdup(r);
    }
}
static void usage(void) {
    puts("BazelSandbox (MXC adapter) 0.1\n"
         "usage: BazelSandbox -W cwd [-T s] [-t s] [-l out] [-L err] [-w p]* [-r p]* [-b p]* [-D] -- cmd...");
}

int main(int argc, char **argv) {
    const char *cwd = NULL, *outp = NULL, *errp = NULL; long timeout = 0; int debug = 0, sep = -1;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--")) { sep = i + 1; break; }
        if (!strcmp(a, "-h")) { usage(); return 0; }
        if (!strcmp(a, "-D")) { debug = 1; continue; }
        if (i + 1 >= argc) { fprintf(stderr, "BazelSandbox: missing value for %s\n", a); return 64; }
        const char *v = argv[++i];
        if (!strcmp(a, "-W")) cwd = v;
        else if (!strcmp(a, "-T")) timeout = atol(v);
        else if (!strcmp(a, "-t")) ; /* kill delay: not supported by wxc-exec */
        else if (!strcmp(a, "-l")) outp = v;
        else if (!strcmp(a, "-L")) errp = v;
        else if (!strcmp(a, "-w")) { if (nrw < MAXP) rw[nrw++] = v; }
        else if (!strcmp(a, "-r")) { if (nro < MAXP) ro[nro++] = v; }
        else if (!strcmp(a, "-b")) { if (ndeny < MAXP) deny[ndeny++] = v; }
        else { fprintf(stderr, "BazelSandbox: unknown flag %s\n", a); usage(); return 64; }
    }
    if (sep < 0 || sep >= argc) { fprintf(stderr, "BazelSandbox: no command after --\n"); return 64; }
    /* Bazel's runner passes no -W: it starts the sandbox with cwd = execroot
     * and the action uses relative paths, so inherit our own cwd. */
    static char cwdbuf[MAX_PATH];
    if (!cwd) { GetCurrentDirectoryA(MAX_PATH, cwdbuf); cwd = cwdbuf; }
    /* Declared outputs do not exist yet when the action runs; a grant on a
     * missing file cannot be applied, so widen it to the parent directory. */
    for (int i = 0; i < nrw; i++) {
        if (GetFileAttributesA(rw[i]) != INVALID_FILE_ATTRIBUTES) continue;
        char *d = _strdup(rw[i]); char *s = strrchr(d, '\\'); char *s2 = strrchr(d, '/');
        if (s2 > s) s = s2;
        if (s && s != d) { *s = 0; rw[i] = d; }
    }

    /* Bazel strips the action environment down to PATH/TEMP/TMP. MXC's
     * AppContainer+DACL fallback tier keeps its ACE state file under the
     * profile and refuses to run without these two. */
    static char lad[MAX_PATH], prof[MAX_PATH];
    if (!getenv("LOCALAPPDATA") && SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, lad) == S_OK) SetEnvironmentVariableA("LOCALAPPDATA", lad);
    if (!getenv("USERPROFILE") && SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, prof) == S_OK) SetEnvironmentVariableA("USERPROFILE", prof);

    char *extra = getenv("BAZEL_MXC_EXTRA_RO");
    if (extra) { extra = _strdup(extra); for (char *t = strtok(extra, ";"); t && nro < MAXP; t = strtok(NULL, ";")) if (*t) ro[nro++] = t; }

    add_targets(ro, &nro); add_targets(rw, &nrw);

    static char cmdline[65536]; cmdline[0] = 0;
    for (int i = sep; i < argc; i++) { if (i > sep) strncat(cmdline, " ", 2); quote_arg(cmdline, sizeof cmdline, argv[i]); }

    char tmp[MAX_PATH], req[MAX_PATH];
    GetTempPathA(MAX_PATH, tmp);
    snprintf(req, sizeof req, "%sbazel-mxc-%lu-%lu.json", tmp, GetCurrentProcessId(), GetTickCount());
    FILE *f = fopen(req, "wb");
    if (!f) { fprintf(stderr, "BazelSandbox: cannot write %s\n", req); return 1; }
    fputs("{\"version\": \"1.0.0\", \"containment\": \"processcontainer\",\n", f);
    fputs(" \"lifecycle\": {\"destroyOnExit\": true},\n", f);
    fputs(" \"process\": {\"commandLine\": ", f); jstr(f, cmdline);
    fputs(", \"cwd\": ", f); jstr(f, cwd);
    /* MXC's default environment is the user's profile block, not ours. Bazel
     * hands the (scrubbed) action environment to the sandbox binary and
     * expects the action to see exactly that, so pass it verbatim. */
    fputs(", \"env\": [", f);
    { char *blk = GetEnvironmentStringsA(); int first = 1;
      for (char *e = blk; *e; e += strlen(e) + 1) {
          if (*e == '=') continue;              /* hidden =C:= cwd entries */
          if (!first) fputs(", ", f); first = 0; jstr(f, e);
      }
      FreeEnvironmentStringsA(blk); }
    fputs("]", f);
    if (timeout > 0) fprintf(f, ", \"timeout\": %ld", timeout * 1000);
    fputs("},\n \"filesystem\": {", f);
    jlist(f, "\"readwritePaths\"", rw, nrw); fputs(", ", f);
    jlist(f, "\"readonlyPaths\"", ro, nro);
    if (ndeny) { fputs(", ", f); jlist(f, "\"deniedPaths\"", deny, ndeny); }
    fputs("}", f);
    /* Bazel grants inputs and outputs, not the execroot itself; on the native
     * tier the cwd can be made enumerable without granting reads. MXC applies
     * the most restrictive intent when a path is listed twice, so only do it
     * when nothing else covers the cwd, and only when asked (the AppContainer
     * fallback tier rejects enumeratePaths outright). */
    int covered = 0;
    for (int i = 0; i < nrw && !covered; i++) covered = !_stricmp(rw[i], cwd);
    for (int i = 0; i < nro && !covered; i++) covered = !_stricmp(ro[i], cwd);
    static const char *enumv[MAXP]; int nenum = 0;
    if (getenv("BAZEL_MXC_ENUM_CWD") && !covered) enumv[nenum++] = cwd;
    /* BAZEL_MXC_ENUM_ANCESTORS=1: the kernel policy does not let a process
     * traverse or query directories above a grant (`dir`, realpath, launching
     * an exe from a granted directory all fail), so list every ancestor of
     * every grant and of the cwd as enumerate-only, unless a grant already
     * covers it. */
    if (getenv("BAZEL_MXC_ENUM_ANCESTORS")) {
        int total = nro + nrw + 1;
        for (int k = 0; k < total; k++) {
            const char *p = k < nro ? ro[k] : k < nro + nrw ? rw[k - nro] : cwd;
            size_t len = strlen(p);
            while (len > 3) {
                while (len > 3 && p[len - 1] != '\\' && p[len - 1] != '/') len--;
                size_t keep = len > 3 ? len - 1 : len;   /* drop the separator, keep "C:\" */
                char *anc = (char *)malloc(keep + 1); memcpy(anc, p, keep); anc[keep] = 0;
                if (len > 3) len--;
                if (!path_covered(anc) && !path_listed(enumv, nenum, anc) && nenum < MAXP) enumv[nenum++] = anc; else free(anc);
            }
        }
    }
    const char *ui = getenv("BAZEL_MXC_UI");
    if (nenum || ui) {
        fputs(",\n \"processContainer\": {", f);
        if (nenum) { fputs("\"filesystem\": {", f); jlist(f, "\"enumeratePaths\"", enumv, nenum); fputs("}", f); }
        /* Tools that import USER32 (cl.exe, node, powershell, ...) die with
         * STATUS_DLL_INIT_FAILED under the default Win32k lockdown; relax it. */
        if (ui) { if (nenum) fputs(", ", f); fputs("\"ui\": {\"isolation\": \"desktop\"}", f); }
        fputs("}", f);
        if (ui) fputs(",\n \"ui\": {\"disable\": false}", f);
    }
    fputs(",\n \"network\": {\"egress\": {\"default\": \"deny\"}, \"ingress\": {\"default\": \"deny\", \"hostLoopback\": \"deny\"}}\n}\n", f);
    fclose(f);

    char wxc[MAX_PATH];
    const char *env_wxc = getenv("BAZEL_MXC_WXC");
    if (env_wxc) strncpy(wxc, env_wxc, MAX_PATH - 1), wxc[MAX_PATH - 1] = 0;
    else { GetModuleFileNameA(NULL, wxc, MAX_PATH); char *s = strrchr(wxc, '\\'); strcpy(s ? s + 1 : wxc, "wxc-exec.exe"); }

    static char child[70000]; child[0] = 0;
    quote_arg(child, sizeof child, wxc); strncat(child, " ", 2); quote_arg(child, sizeof child, req);
    if (debug) strncat(child, " --debug", 9);

    SECURITY_ATTRIBUTES sa = { sizeof sa, NULL, TRUE };
    HANDLE ho = NULL, he = NULL;
    STARTUPINFOA si; ZeroMemory(&si, sizeof si); si.cb = sizeof si; si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    if (outp) { ho = CreateFileA(outp, GENERIC_WRITE, FILE_SHARE_READ, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL); if (ho != INVALID_HANDLE_VALUE) si.hStdOutput = ho; }
    if (errp) { he = CreateFileA(errp, GENERIC_WRITE, FILE_SHARE_READ, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL); if (he != INVALID_HANDLE_VALUE) si.hStdError = he; }
    PROCESS_INFORMATION pi;
    DWORD code = 1;
    if (!CreateProcessA(NULL, child, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        fprintf(stderr, "BazelSandbox: CreateProcess(%s) failed: %lu\n", wxc, GetLastError());
    } else {
        WaitForSingleObject(pi.hProcess, INFINITE);
        GetExitCodeProcess(pi.hProcess, &code);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    }
    if (ho && ho != INVALID_HANDLE_VALUE) CloseHandle(ho);
    if (he && he != INVALID_HANDLE_VALUE) CloseHandle(he);
    if (getenv("BAZEL_MXC_KEEP")) fprintf(stderr, "BazelSandbox: request kept at %s\n", req); else DeleteFileA(req);
    return (int)code;
}
