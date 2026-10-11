//! `BazelSandbox.exe`: the binary Bazel's `windows-sandbox` spawn strategy
//! invokes (`WindowsSandboxUtil.java`), implemented on Microsoft Execution
//! Containers through the `mxc-sdk` crate. The contained process is created
//! in-process (`CreateProcessSecurityEnvironment` + `CreateProcessW`); no
//! `wxc-exec.exe` hop.
//!
//! ```text
//! BazelSandbox [-W cwd] [-T timeout_s] [-t kill_delay_s] [-l stdout] [-L stderr]
//!              (-w rw_path)* (-r ro_path)* (-b denied_path)* [-D] [@params]* -- cmd args...
//! ```
//!
//! `@params` names a file with one argument per line and is expanded in
//! place; Bazel uses it when the path lists would exceed the Windows
//! command-line limit.
//!
//! Bazel passes the declared inputs as `-r`, the outputs and `TMP` as `-w`,
//! starts the binary with cwd = execroot and never passes `-W`. The action
//! environment (already scrubbed by Bazel) is this process's environment and
//! is handed to the container verbatim.
//!
//! Environment knobs (reach the adapter through `--action_env`):
//!
//! * `BAZEL_MXC_EXTRA_RO=<p>;<p>`  extra read-only roots for toolchains Bazel
//!   does not declare as inputs (MSVC, Windows Kits, node, ...).
//! * `BAZEL_MXC_DIR_GRANTS=1`      grant the parent directory of each
//!   read-only input file instead of the file (policy setup costs ~1 ms per
//!   path; actions with thousands of inputs get much cheaper, at the price of
//!   exposing sibling files).
//! * `BAZEL_MXC_NO_ENUM=1`         do not list the cwd and the ancestors of
//!   every grant as enumerate-only (they are needed on PSEC 1.1 for `dir`,
//!   realpath and launching executables from granted directories).
//! * `BAZEL_MXC_NO_UI=1`           keep the default Win32k lockdown. Anything
//!   importing USER32 (cl.exe, java, node, ...) then fails with
//!   STATUS_DLL_INIT_FAILED.
//! * `BAZEL_MXC_TIMING=<file>`     append one line per action with policy-prep,
//!   spawn and total milliseconds and the grant counts.
//! * `BAZEL_MXC_DEBUG=1` (or `-D`) print the effective policy to stderr.

use std::collections::HashSet;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;
use std::process;
use std::thread;
use std::time::Instant;

use mxc_sdk::v1::configs::{
    ProcessContainerConfig, ProcessContainerFilesystem, ProcessContainerUi,
    ProcessContainerUiIsolation,
};
use mxc_sdk::v1::{
    self, ContainerRequest, Containment, FilesystemPolicy, NetworkAction, NetworkEgressPolicy,
    NetworkIngressPolicy, NetworkPolicy, SpawnOptions, TelemetryConfig, UiPolicy, WaitResult,
};

const USAGE: &str = "usage: BazelSandbox [-W cwd] [-T s] [-t s] [-l out] [-L err] [-w p]* [-r p]* [-b p]* [-D] -- cmd...";

#[derive(Default)]
struct Args {
    cwd: Option<String>,
    timeout_s: Option<u32>,
    stdout: Option<String>,
    stderr: Option<String>,
    rw: Vec<String>,
    ro: Vec<String>,
    deny: Vec<String>,
    debug: bool,
    cmd: Vec<String>,
}

/// Expand `@file` arguments (one argument per line) in place, so the path
/// lists can be handed over without hitting CreateProcessW's 32 767-character
/// command-line limit. Only arguments before `--` are expanded.
fn expand_params(raw: Vec<String>) -> Result<Vec<String>, String> {
    let mut out = Vec::with_capacity(raw.len());
    let mut after_sep = false;
    for a in raw {
        if after_sep || a == "--" {
            after_sep = after_sep || a == "--";
            out.push(a);
        } else if let Some(file) = a.strip_prefix('@') {
            let text = fs::read_to_string(file).map_err(|e| format!("cannot read params file {file}: {e}"))?;
            out.extend(text.lines().filter(|l| !l.is_empty()).map(|l| l.trim_end_matches('\r').to_string()));
        } else {
            out.push(a);
        }
    }
    Ok(out)
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args::default();
    let mut it = expand_params(env::args().skip(1).collect())?.into_iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--" => {
                a.cmd = it.collect();
                if a.cmd.is_empty() {
                    return Err("no command after --".into());
                }
                return Ok(a);
            }
            "-h" | "--help" => {
                println!("BazelSandbox (MXC adapter) 0.2\n{USAGE}");
                process::exit(0);
            }
            "-D" => a.debug = true,
            _ => {
                let v = it.next().ok_or_else(|| format!("missing value for {flag}"))?;
                match flag.as_str() {
                    "-W" => a.cwd = Some(v),
                    "-T" => a.timeout_s = v.parse().ok(),
                    "-t" => {} // kill delay after timeout: not modelled by MXC
                    "-l" => a.stdout = Some(v),
                    "-L" => a.stderr = Some(v),
                    "-w" => a.rw.push(v),
                    "-r" => a.ro.push(v),
                    "-b" => a.deny.push(v),
                    _ => return Err(format!("unknown flag {flag}\n{USAGE}")),
                }
            }
        }
    }
    Err("no command after --".into())
}

/// Comparison key: lower case, backslashes, no trailing separator (except on a
/// drive root such as `C:\`).
fn key(p: &str) -> String {
    let mut k: String = p
        .chars()
        .map(|c| if c == '/' { '\\' } else { c.to_ascii_lowercase() })
        .collect();
    while k.len() > 3 && k.ends_with('\\') {
        k.pop();
    }
    k
}


/// `\\?\C:\x` -> `C:\x`; UNC targets are left out.
fn canonical(p: &str) -> Option<String> {
    let c = fs::canonicalize(p).ok()?;
    let s = c.to_string_lossy().into_owned();
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        let _ = rest;
        return None;
    }
    Some(s.strip_prefix(r"\\?\").unwrap_or(&s).to_string())
}

/// Bazel's execroot is a forest of symlinks/junctions into the source tree and
/// MXC evaluates its policy on the resolved target, so grant that too.
fn add_targets(v: &mut Vec<String>) {
    let mut extra = Vec::new();
    for p in v.iter() {
        if let Some(t) = canonical(p) {
            if key(&t) != key(p) {
                extra.push(t);
            }
        }
    }
    v.extend(extra);
}

fn dedupe(v: &mut Vec<String>) {
    let mut seen = std::collections::HashSet::new();
    v.retain(|p| seen.insert(key(p)));
}

/// Drop entries that are inside another entry of the same list. Sorting the
/// comparison keys puts every path right after the directories above it, so
/// one pass suffices (the old pairwise check was quadratic and dominated the
/// per-action cost once inputs reached the thousands).
fn prune_nested(v: &mut Vec<String>) {
    let mut keyed: Vec<(String, String)> = v.drain(..).map(|p| (key(&p), p)).collect();
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    let mut kept_dirs: Vec<String> = Vec::new();
    for (k, p) in keyed {
        let nested = kept_dirs
            .last()
            .map(|d| k.len() > d.len() && k.starts_with(d.as_str()) && (d.ends_with('\\') || k.as_bytes()[d.len()] == b'\\'))
            .unwrap_or(false);
        if nested {
            continue;
        }
        kept_dirs.push(k);
        v.push(p);
    }
}

/// Windows command line from argv, per the CRT's parsing rules.
fn quote_arg(out: &mut String, a: &str) {
    if !a.is_empty() && !a.contains([' ', '\t', '"']) {
        out.push_str(a);
        return;
    }
    out.push('"');
    let mut bs = 0;
    for c in a.chars() {
        match c {
            '\\' => bs += 1,
            '"' => {
                out.extend(std::iter::repeat('\\').take(bs * 2 + 1));
                out.push('"');
                bs = 0;
            }
            _ => {
                out.extend(std::iter::repeat('\\').take(bs));
                out.push(c);
                bs = 0;
            }
        }
    }
    out.extend(std::iter::repeat('\\').take(bs * 2));
    out.push('"');
}

fn pump(src: Option<Box<dyn Read + Send>>, dest: Option<String>, to_stderr: bool) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let Some(mut src) = src else { return };
        let mut sink: Box<dyn Write> = match dest {
            Some(path) => match File::create(&path) {
                Ok(f) => Box::new(f),
                Err(e) => {
                    eprintln!("BazelSandbox: cannot create {path}: {e}");
                    if to_stderr { Box::new(io::stderr()) } else { Box::new(io::stdout()) }
                }
            },
            None if to_stderr => Box::new(io::stderr()),
            None => Box::new(io::stdout()),
        };
        let _ = io::copy(&mut src, &mut sink);
        let _ = sink.flush();
    })
}

fn main() {
    let t0 = Instant::now();
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("BazelSandbox: {e}");
            process::exit(64);
        }
    };
    let debug = args.debug || env::var_os("BAZEL_MXC_DEBUG").is_some();
    let dir_grants = env::var_os("BAZEL_MXC_DIR_GRANTS").is_some();
    let enumerate = env::var_os("BAZEL_MXC_NO_ENUM").is_none();
    let ui = env::var_os("BAZEL_MXC_NO_UI").is_none();

    // Bazel never passes -W: it starts us with cwd = execroot.
    let cwd = args.cwd.clone().unwrap_or_else(|| {
        env::current_dir().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default()
    });

    // Declared outputs do not exist yet and the kernel policy cannot grant a
    // missing file, so widen those grants to the parent directory.
    let mut rw: Vec<String> = args
        .rw
        .iter()
        .map(|p| {
            if Path::new(p).exists() {
                p.clone()
            } else {
                Path::new(p).parent().map(|d| d.to_string_lossy().into_owned()).unwrap_or_else(|| p.clone())
            }
        })
        .collect();
    let mut ro = args.ro.clone();
    if let Ok(extra) = env::var("BAZEL_MXC_EXTRA_RO") {
        ro.extend(extra.split(';').filter(|s| !s.is_empty()).map(String::from));
    }
    add_targets(&mut ro);
    add_targets(&mut rw);
    if dir_grants {
        ro = ro
            .into_iter()
            .map(|p| {
                if Path::new(&p).is_file() {
                    Path::new(&p).parent().map(|d| d.to_string_lossy().into_owned()).unwrap_or(p)
                } else {
                    p
                }
            })
            .collect();
    }
    dedupe(&mut ro);
    dedupe(&mut rw);
    prune_nested(&mut ro);
    prune_nested(&mut rw);

    // MXC applies the most restrictive intent to a path listed twice, so never
    // enumerate a path some grant already covers: a path is covered when it or
    // one of its ancestors is a grant. For every grant (and the cwd) walk its
    // ancestor chain top-down and enumerate the ancestors above the first grant.
    let grant_keys: HashSet<String> = ro.iter().chain(rw.iter()).map(|g| key(g)).collect();
    let mut enumerate_paths: Vec<String> = Vec::new();
    if enumerate {
        let mut seen: HashSet<String> = HashSet::new();
        for p in ro.iter().chain(rw.iter()).chain(std::iter::once(&cwd)) {
            let mut chain: Vec<&Path> = Vec::new();
            let mut cur: Option<&Path> = if std::ptr::eq(p, &cwd) { Some(Path::new(p)) } else { Path::new(p).parent() };
            while let Some(d) = cur {
                if d.as_os_str().is_empty() {
                    break;
                }
                chain.push(d);
                cur = d.parent();
            }
            let mut covered = false;
            for d in chain.into_iter().rev() {
                let s = d.to_string_lossy();
                let k = key(&s);
                if grant_keys.contains(&k) {
                    covered = true;
                }
                if !covered && seen.insert(k) {
                    enumerate_paths.push(s.into_owned());
                }
            }
        }
    }

    // Bazel hands over argv[0] as it appears in the action, e.g.
    // `external/+winsdk_configure+local_config_winsdk/rc_x64.bat`: relative and
    // with forward slashes. CreateProcess finds the batch file, but the cmd.exe
    // it starts for it parses the `/` as switches and fails with "'external' is
    // not recognized". Bazel's local runner resolves argv[0] against the
    // execroot first; do the same and use backslashes.
    let mut argv = args.cmd.clone();
    if let Some(first) = argv.first_mut() {
        if first.contains(['\\', '/']) {
            let p = Path::new(first.as_str());
            let abs = if p.is_absolute() { p.to_path_buf() } else { Path::new(&cwd).join(p) };
            if abs.exists() {
                *first = abs.to_string_lossy().replace('/', "\\");
            }
        }
    }
    let mut command = String::new();
    for (i, a) in argv.iter().enumerate() {
        if i > 0 {
            command.push(' ');
        }
        quote_arg(&mut command, a);
    }

    // MXC's "default environment" is the user's profile block, not ours.
    // Bazel expects the action to see exactly the environment it gave us.
    // Bazel strips the environment down to PATH/TEMP/TMP; MXC refuses to
    // launch without USERPROFILE and LOCALAPPDATA present (presence only).
    #[allow(deprecated)]
    let home = env::home_dir().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
    let mut environment: Vec<(String, String)> = env::vars_os()
        .filter_map(|(k, v)| {
            let k = k.to_string_lossy().into_owned();
            (!k.is_empty() && !k.starts_with('=')).then(|| (k, v.to_string_lossy().into_owned()))
        })
        .collect();
    for (name, value) in [("USERPROFILE", home.clone()), ("LOCALAPPDATA", format!("{home}\\AppData\\Local"))] {
        if !environment.iter().any(|(k, _)| k.eq_ignore_ascii_case(name)) {
            environment.push((name.to_string(), value));
        }
    }

    let mut pc = ProcessContainerConfig::default();
    let mut fs_cfg = ProcessContainerFilesystem::default();
    fs_cfg.enumerate_paths = enumerate_paths.clone();
    pc.filesystem = Some(fs_cfg);
    let mut pc_ui = ProcessContainerUi::default();
    if ui {
        // Tools that import USER32 die with STATUS_DLL_INIT_FAILED under the
        // default Win32k lockdown.
        pc_ui.isolation = ProcessContainerUiIsolation::Desktop;
    }
    pc.ui = Some(pc_ui);

    let request = ContainerRequest {
        filesystem: Some(FilesystemPolicy {
            readwrite_paths: rw.clone(),
            readonly_paths: ro.clone(),
            denied_paths: args.deny.clone(),
            clear_policy_on_exit: None,
        }),
        network: Some(NetworkPolicy {
            egress: Some(NetworkEgressPolicy { default: Some(NetworkAction::Deny), allow: None, deny: None }),
            ingress: Some(NetworkIngressPolicy { default: Some(NetworkAction::Deny), host_loopback: Some(NetworkAction::Deny) }),
            runtime_config: None,
        }),
        ui: Some(UiPolicy { disable: !ui, ..UiPolicy::default() }),
        timeout_ms: args.timeout_s.map(|s| s.saturating_mul(1000)),
        containment: Containment::ProcessContainer(pc),
        container_name: None,
        working_directory: Some(cwd.clone()),
        environment: Some(environment),
        inherit_default_environment: Some(false),
        ..ContainerRequest::new(command.clone())
    };

    if debug {
        eprintln!("BazelSandbox: cwd={cwd}\n  command={command}");
        for p in &rw { eprintln!("  rw {p}"); }
        for p in &ro { eprintln!("  ro {p}"); }
        for p in &args.deny { eprintln!("  deny {p}"); }
        for p in &enumerate_paths { eprintln!("  enum {p}"); }
    }

    let t_prep = t0.elapsed();
    let opts = SpawnOptions { telemetry: Some(TelemetryConfig { enabled: Some(false) }) };
    let mut child = match v1::spawn(request, opts) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("BazelSandbox: MXC spawn failed: {e}");
            if let Some(hint) = &e.remediation { eprintln!("  try: {hint}"); }
            process::exit(1);
        }
    };
    let t_spawn = t0.elapsed();
    let out = pump(child.take_stdout(), args.stdout.clone(), false);
    let err = pump(child.take_stderr(), args.stderr.clone(), true);
    let code = match child.wait() {
        Ok(WaitResult::Exited(code)) => code,
        Ok(WaitResult::TimedOut) => {
            eprintln!("BazelSandbox: action timed out after {} s", args.timeout_s.unwrap_or(0));
            124
        }
        Err(e) => {
            eprintln!("BazelSandbox: wait failed: {e}");
            1
        }
    };
    for w in child.warnings() {
        if debug { eprintln!("BazelSandbox: warning: {w}"); }
    }
    drop(child);
    let _ = out.join();
    let _ = err.join();
    let t_total = t0.elapsed();

    if let Ok(path) = env::var("BAZEL_MXC_TIMING") {
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(
                f,
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                t_prep.as_millis(),
                (t_spawn - t_prep).as_millis(),
                (t_total - t_spawn).as_millis(),
                t_total.as_millis(),
                ro.len(),
                rw.len(),
                enumerate_paths.len(),
                code
            );
        }
    }
    process::exit(code);
}
