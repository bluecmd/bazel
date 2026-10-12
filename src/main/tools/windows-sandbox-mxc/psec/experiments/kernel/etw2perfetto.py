#!/usr/bin/env python3
"""Convert a WPR/xperf kernel trace (.etl) into Perfetto's JSON trace-event format.

The system provider must have been recorded with at least ProcessThread, Loader,
CSwitch, ReadyThread, SystemCall, SampledProfile (+stacks) and FileIO/FileIOInit
(see psec.wprp).  The etl-parser package (pip install etl-parser) is used only for
the file/buffer framing; the MOF payloads are decoded here because etl-parser
does not decode CSwitch, SysClEnter/Exit, SampledProfile, StackWalk or FileIo.

What ends up in the trace:
  * one fake process "CPU" with a track per processor: who was running when
    (from CSwitch), slices named "<image> <tid>"
  * per thread: system calls as slices (SysClEnter -> SysClExit, attributed to
    the thread that the CPU's CSwitch stream says was current), named after the
    kernel entry point (symbol table from `ln` output) with NTSTATUS as arg
  * per thread: FileIo operations as slices nested inside the system call
    (Create -> OperationEnd paired by IrpPtr), with path, create options, status
  * per thread: profiler samples as instants, with the module!function of the
    sampled IP and the captured stack as args
  * flows from a ReadyThread (waker) to the readied thread's next switch-in,
    which is what makes the ALPC round trips client -> AppInfo broker visible
  * process start/end instants

Usage:
  python -I etw2perfetto.py trace.etl out.json[.gz] --etl-parser <site-packages>
      [--modules modules.txt] [--bfs-funcs bfs-funcs.txt] [--symbols ln.out ...]
      [--qpc-hz 10000000] [--focus nttest.exe,BazelSandbox.exe,svchost.exe:Appinfo]
"""
import argparse, collections, gzip, json, re, struct, sys

ap = argparse.ArgumentParser()
ap.add_argument('etl')
ap.add_argument('out')
ap.add_argument('--etl-parser', required=True, help='site-packages directory holding etl-parser')
ap.add_argument('--modules', help='modules.txt: "<name> <base-hex> <size-hex>" per line (from `lm`)')
ap.add_argument('--bfs-funcs', help='bfs-funcs.txt: "<rva-start> <rva-end> <name>" per line')
ap.add_argument('--symbols', action='append', default=[], help='"<addr-hex>  <symbol>" lines (ln output)')
ap.add_argument('--user-symbols', action='append', default=[], help='<module>=<file> with "<rva-start> <rva-end> <name>" lines (IDA export) for user-mode frames')
ap.add_argument('--qpc-hz', type=float, default=10e6, help='QPC frequency of the trace clock')
ap.add_argument('--focus', default='nttest.exe,BazelSandbox.exe,svchost.exe:Appinfo',
                help='comma list of image[:cmdline-substring]; these processes get syscall/FileIo/sample detail')
ap.add_argument('--debug-stacks', action='store_true')
ap.add_argument('--all-syscalls', action='store_true', help='emit syscalls for every process, not only focus ones')
args = ap.parse_args()

sys.path.insert(0, args.etl_parser)
import etl.etl as etlmod
from etl.etl import ChunkParser

# ---------------------------------------------------------------- symbols
modules = []           # (base, end, name)
if args.modules:
    for line in open(args.modules):
        p = line.split()
        if len(p) >= 3:
            try:
                base = int(p[1], 16); size = int(p[2], 16)
            except ValueError:
                continue
            modules.append((base, base + size, p[0]))
    modules.sort()
bfs_funcs = []         # (rva_start, rva_end, name)
if args.bfs_funcs:
    for line in open(args.bfs_funcs):
        p = line.split()
        if len(p) >= 3:
            bfs_funcs.append((int(p[0], 16), int(p[1], 16), p[2]))
    bfs_funcs.sort()
symtab = {}
for fn in args.symbols:
    for line in open(fn):
        m = re.match(r'^\s*([0-9a-fA-F`]{8,})\s+(\S+)', line)
        if m:
            symtab[int(m.group(1).replace('`', ''), 16)] = m.group(2)

user_funcs = {}        # module name (lower) -> sorted [(rva_start, rva_end, name)]
for spec in args.user_symbols:
    mod, _, fn = spec.partition('=')
    lst = []
    for line in open(fn):
        p = line.split(None, 2)
        if len(p) == 3:
            try: lst.append((int(p[0], 16), int(p[1], 16), p[2].strip()))
            except ValueError: pass
    user_funcs[mod.lower()] = sorted(lst)
user_images = collections.defaultdict(list)   # pid -> sorted [(base, size, name)]
def user_module_of(pid, addr):
    lst = user_images.get(pid)
    if not lst: return None
    lo, hi = 0, len(lst)
    while lo < hi:
        mid = (lo + hi) // 2
        if lst[mid][0] + lst[mid][1] <= addr: lo = mid + 1
        elif lst[mid][0] > addr: hi = mid
        else: return lst[mid]
    return None
def symbolize_user(pid, addr):
    m = user_module_of(pid, addr)
    if not m: return 'user 0x%x' % addr
    rva = addr - m[0]; name = m[2]
    fl = user_funcs.get(name.lower())
    if fl:
        lo, hi = 0, len(fl)
        while lo < hi:
            mid = (lo + hi) // 2
            if fl[mid][1] <= rva: lo = mid + 1
            elif fl[mid][0] > rva: hi = mid
            else: return '%s!%s+0x%x' % (name, fl[mid][2], rva - fl[mid][0])
    return '%s+0x%x' % (name, rva)

def module_of(addr):
    lo, hi = 0, len(modules)
    while lo < hi:
        mid = (lo + hi) // 2
        if modules[mid][1] <= addr: lo = mid + 1
        elif modules[mid][0] > addr: hi = mid
        else: return modules[mid]
    return None

def symbolize(addr, pid=-1):
    if addr < 0x800000000000:
        return symbolize_user(pid, addr)
    if addr in symtab:
        return symtab[addr]
    m = module_of(addr)
    if not m:
        return 'user 0x%x' % addr if addr < 0x800000000000 else '0x%x' % addr
    rva = addr - m[0]
    if m[2] == 'bfs':
        for s, e, n in bfs_funcs:
            if s <= rva < e:
                return 'bfs!%s+0x%x' % (n, rva - s)
    return '%s+0x%x' % (m[2], rva)

# ---------------------------------------------------------------- decode
data = open(args.etl, 'rb').read()
f = etlmod.build_from_stream(data)

GROUP_THREAD = 'EVENT_TRACE_GROUP_THREAD'
GROUP_PROCESS = 'EVENT_TRACE_GROUP_PROCESS'
GROUP_PERFINFO = 'EVENT_TRACE_GROUP_PERFINFO'
GROUP_STACKWALK = 'EVENT_TRACE_GROUP_STACKWALK'
GROUP_FILE = 'EVENT_TRACE_GROUP_FILE'

events = []   # (ts, seq, cpu, kind, payload...)
seq = 0
proc_name = {}      # pid -> image
proc_cmd = {}       # pid -> command line
thread_pid = {}     # tid -> pid
thread_name = {}

def cstr(b, off):
    e = b.find(b'\0', off)
    return b[off:e].decode('latin-1'), e + 1

def wstr(b, off):
    e = off
    while e + 1 < len(b) and b[e:e+2] != b'\0\0':
        e += 2
    return b[off:e].decode('utf-16-le', 'replace'), e + 2

def parse_process(b):
    # Process_V4 (64-bit): UniqueProcessKey(8) ProcessId(4) ParentId(4) SessionId(4)
    # ExitStatus(4) DirectoryTableBase(8) Flags(4) UserSID(var) ImageFileName(str) CommandLine(wstr)
    pid = struct.unpack_from('<I', b, 8)[0]
    off = 36
    # UserSID: pointer-sized "attributes" pair; if the first pointer is zero the field is one pointer
    if struct.unpack_from('<Q', b, off)[0] == 0:
        off += 8
    else:
        off += 16
        sub = b[off + 1]
        off += 8 + 4 * sub
    try:
        img, off = cstr(b, off)
        cmd, off = wstr(b, off)
    except Exception:
        m = re.search(rb'([\x20-\x7e]+\.exe)\0', b)
        img = m.group(1).decode() if m else '?'
        cmd = ''
    return pid, img, cmd

for ch in f.chunks:
    cpu = ch.header.wnode.client_context.processor_index
    for ev in ChunkParser.parse(ch.payload):
        v = ev.value
        seq += 1
        if ev.type == 'PerfInfoTraceRecord':
            g = str(v.header.group); t = v.header.type; ts = v.timestamp; b = bytes(v.mof_data)
            if g == GROUP_PERFINFO and t == 51:
                events.append((ts, seq, cpu, 'enter', struct.unpack_from('<Q', b, 0)[0]))
            elif g == GROUP_PERFINFO and t == 52:
                events.append((ts, seq, cpu, 'exit', struct.unpack_from('<I', b, 0)[0]))
            elif g == GROUP_THREAD and t == 36:
                nt, ot, npri, opri, pcs, sp, owr, owm, ost, oip = struct.unpack_from('<IIBBBBBBBB', b, 0)
                events.append((ts, seq, cpu, 'cswitch', nt, ot, npri, opri, owr, ost))
            elif g == GROUP_THREAD and t == 50:
                events.append((ts, seq, cpu, 'ready', struct.unpack_from('<I', b, 0)[0]))
            elif g == GROUP_PERFINFO and t == 46:
                ip, tid, cnt = struct.unpack_from('<QIH', b, 0)
                events.append((ts, seq, cpu, 'sample', ip, tid))
            elif g == GROUP_STACKWALK and t == 32:
                ets, spid, stid = struct.unpack_from('<QII', b, 0)
                n = (len(b) - 16) // 8
                frames = struct.unpack_from('<%dQ' % n, b, 16)
                events.append((ts, seq, cpu, 'stack', ets, spid, stid, frames))
            elif g == 'EVENT_TRACE_GROUP_IMAGE' and t in (3, 10):
                ibase, isize, ipid = struct.unpack_from('<QQI', b, 0)
                user_images[ipid].append((ibase, isize, wstr(b, 56)[0].rsplit('\\', 1)[-1]))
            elif g == GROUP_PROCESS and t in (3, 4):
                pid, img, cmd = parse_process(b)
                proc_name.setdefault(pid, img); proc_cmd.setdefault(pid, cmd)
            elif g == GROUP_THREAD and t == 72:
                pid, tid = struct.unpack_from('<II', b, 0)
                thread_name[tid] = wstr(b, 8)[0]
        elif ev.type == 'SystemTraceRecord':
            h = v.system_header; g = str(h.header.group); t = h.header.type
            ts = h.system_time; tid = h.thread_id; pid = h.process_id; b = bytes(v.mof_data)
            if g == GROUP_FILE:
                events.append((ts, seq, cpu, 'file', t, tid, pid, b))
            elif g == GROUP_THREAD and t in (1, 2, 3, 4):
                p, th = struct.unpack_from('<II', b, 0)
                thread_pid[th] = p
            elif (g == GROUP_PROCESS and t == 10) or (g == 'EVENT_TRACE_GROUP_IMAGE' and t in (3, 10)):
                ibase, isize, ipid = struct.unpack_from('<QQI', b, 0)
                user_images[ipid].append((ibase, isize, wstr(b, 56)[0].rsplit('\\', 1)[-1]))
            elif g == GROUP_PROCESS and t in (1, 2):
                p, img, cmd = parse_process(b)
                proc_name.setdefault(p, img); proc_cmd.setdefault(p, cmd)
                events.append((ts, seq, cpu, 'process', t, p, img))
            elif g == GROUP_THREAD and t == 72:
                p, th = struct.unpack_from('<II', b, 0)
                thread_name[th] = wstr(b, 8)[0]

events.sort(key=lambda e: (e[0], e[1]))
for pid in user_images: user_images[pid] = sorted(set(user_images[pid]))
t0 = events[0][0]
tick_us = 1e6 / args.qpc_hz
def us(ts):
    return round((ts - t0) * tick_us, 1)

# ---------------------------------------------------------------- focus set
focus = set()
for spec in args.focus.split(','):
    spec = spec.strip()
    if not spec: continue
    img, _, sub = spec.partition(':')
    for pid, name in proc_name.items():
        if name.lower() == img.lower() and (not sub or sub.lower() in proc_cmd.get(pid, '').lower()):
            focus.add(pid)
focus.add(4)  # System: bfs policy-store writes happen on system threads
def label(pid):
    n = proc_name.get(pid, 'pid %d' % pid)
    if n.lower() == 'svchost.exe':
        m = re.search(r'-s\s+(\S+)', proc_cmd.get(pid, ''))
        if m: n = 'svchost (%s)' % m.group(1)
    return n

# ---------------------------------------------------------------- emit
out = []
CPU_PID = 999000
out.append({'ph': 'M', 'name': 'process_name', 'pid': CPU_PID, 'args': {'name': 'CPU scheduling'}})
out.append({'ph': 'M', 'name': 'process_sort_index', 'pid': CPU_PID, 'args': {'sort_index': 100}})
ncpu = max(e[2] for e in events) + 1
for c in range(ncpu):
    out.append({'ph': 'M', 'name': 'thread_name', 'pid': CPU_PID, 'tid': CPU_PID + c, 'args': {'name': 'CPU %d' % c}})

cur = {}                 # cpu -> (tid, ts of switch-in)
pending_sys = collections.defaultdict(list)   # tid -> stack of (ts, addr); Zw* calls from kernel mode (bfs.sys) nest inside the user call
pending_irp = {}         # irp -> (ts, tid, pid, name, args)
fobj_path = {}           # FileObject -> path
ready_pending = {}       # tid -> (flow id, waker ts) for threads readied by a focus thread
last_sample = {}         # tid -> index in out of its last sample instant
flow_id = 0
stats = collections.Counter()
seen_pids = set()

NONRETURNING = {'NtContinue', 'NtContinueEx', 'NtCallbackReturn', 'NtRaiseException', 'NtTerminateThread', 'NtTerminateProcess'}
FILE_OPS = {64: 'Create', 65: 'Cleanup', 66: 'Close', 67: 'Read', 68: 'Write', 69: 'SetInfo',
            70: 'Delete', 71: 'Rename', 72: 'DirEnum', 73: 'Flush', 74: 'QueryInfo',
            75: 'FSControl', 77: 'DirNotify', 79: 'RenamePath', 80: 'DeletePath',
            81: 'RenamePath', 82: 'SetLinkPath', 83: 'SetLinkPath', 84: 'CreateNewFile', 86: 'CreateNewFile'}

def short_path(p):
    p = re.sub(r'^\\Device\\HarddiskVolume\d+', '', p)
    return p

for e in events:
    ts, _, cpu, kind = e[:4]
    if kind == 'cswitch':
        nt, ot, npri, opri, owr, ost = e[4:]
        prev = cur.get(cpu)
        if prev and prev[0] != 0:
            ppid = thread_pid.get(prev[0], -1)
            out.append({'ph': 'X', 'pid': CPU_PID, 'tid': CPU_PID + cpu, 'ts': us(prev[1]), 'dur': us(ts) - us(prev[1]),
                        'name': '%s %d' % (label(ppid), prev[0]), 'cat': 'sched',
                        'args': {'pid': ppid, 'tid': prev[0], 'old_wait_reason': owr, 'old_state': ost, 'old_pri': opri}})
        cur[cpu] = (nt, ts)
        if nt in ready_pending:
            fid, wts = ready_pending.pop(nt)
            npid = thread_pid.get(nt, -1)
            out.append({'ph': 'f', 'bp': 'e', 'cat': 'wake', 'name': 'wake', 'id': fid, 'pid': npid, 'tid': nt, 'ts': us(ts)})
            stats['flows'] += 1
    elif kind == 'ready':
        target = e[4]
        c = cur.get(cpu)
        if not c: continue
        waker = c[0]; wpid = thread_pid.get(waker, -1); tpid = thread_pid.get(target, -1)
        if wpid in focus and tpid in focus and wpid != 4 and tpid != 4 and waker != target:
            flow_id += 1
            out.append({'ph': 's', 'cat': 'wake', 'name': 'wake', 'id': flow_id, 'pid': wpid, 'tid': waker, 'ts': us(ts)})
            ready_pending[target] = (flow_id, ts)
    elif kind == 'enter':
        c = cur.get(cpu)
        if not c: stats['enter_no_thread'] += 1; continue
        nm = symtab.get(e[4], '')
        if nm.replace('nt!', '') in NONRETURNING:
            # these never produce a SysClExit: the thread resumes an interrupted user context
            # (NtContinue, thread start) or returns into the syscall that made the user-mode callback
            pid = thread_pid.get(c[0], -1)
            if args.all_syscalls or pid in focus:
                out.append({'ph': 'i', 's': 't', 'pid': pid, 'tid': c[0], 'ts': us(ts), 'cat': 'syscall', 'name': nm.replace('nt!', '')})
            continue
        pending_sys[c[0]].append((ts, e[4]))
    elif kind == 'exit':
        c = cur.get(cpu)
        if not c: continue
        tid = c[0]; st = pending_sys.get(tid)
        if not st: stats['exit_unpaired'] += 1; continue
        p = st.pop()
        pid = thread_pid.get(tid, -1)
        if not (args.all_syscalls or pid in focus): continue
        name = symtab.get(p[1], 'syscall 0x%x' % p[1]).replace('nt!', '')
        out.append({'ph': 'X', 'pid': pid, 'tid': tid, 'ts': us(p[0]), 'dur': us(ts) - us(p[0]), 'name': name,
                    'cat': 'syscall' if not st else 'zwcall', 'args': {'status': '0x%08x' % e[4], 'depth': len(st)}})
        seen_pids.add(pid); stats['syscalls'] += 1
    elif kind == 'file':
        t, tid, pid, b = e[4:]
        if t == 76:
            irp, extra, status = struct.unpack_from('<QQI', b, 0)
            p = pending_irp.pop(irp, None)
            if not p: stats['opend_unpaired'] += 1; continue
            sts, stid, spid, name, a = p
            a['status'] = '0x%08x' % status
            if name.startswith('Read') or name.startswith('Write') or name.startswith('DirEnum'):
                a['bytes'] = extra
            out.append({'ph': 'X', 'pid': spid, 'tid': stid, 'ts': us(sts), 'dur': us(ts) - us(sts), 'name': name,
                        'cat': 'fileio', 'args': a})
            stats['fileio'] += 1
            continue
        if pid not in focus and not args.all_syscalls:
            continue
        op = FILE_OPS.get(t, 'FileIo#%d' % t)
        a = {}
        if t == 64:
            irp, fo, ttid, copt, fattr, share = struct.unpack_from('<QQIIII', b, 0)
            path = wstr(b, 32)[0]
            fobj_path[fo] = path
            a = {'path': path, 'create_options': '0x%08x' % copt, 'share': share,
                 'disposition': copt >> 24, 'file_attributes': '0x%x' % fattr}
            name = 'Create %s' % short_path(path)
        elif t in (65, 66, 73):
            irp, fo, fk = struct.unpack_from('<QQQ', b, 0)
            name = '%s %s' % (op, short_path(fobj_path.get(fo, '?')))
        elif t in (67, 68):
            off, irp, fo, fk, ttid, size, flags = struct.unpack_from('<QQQQIII', b, 0)
            a = {'offset': off, 'size': size, 'flags': '0x%x' % flags}
            name = '%s %s' % (op, short_path(fobj_path.get(fo, '?')))
        elif t in (69, 70, 71, 74, 75):
            irp, fo, fk, extra, ttid, cls = struct.unpack_from('<QQQQII', b, 0)
            a = {'class': '0x%x' % cls}
            name = '%s %s' % (op, short_path(fobj_path.get(fo, '?')))
        elif t in (72, 77):
            irp, fo, fk, ttid, ln, cls, idx = struct.unpack_from('<QQQIIII', b, 0)
            a = {'class': cls, 'length': ln, 'pattern': wstr(b, 44)[0]}
            name = '%s %s' % (op, short_path(fobj_path.get(fo, '?')))
        else:
            irp, fo = struct.unpack_from('<QQ', b, 0)
            name = '%s %s' % (op, short_path(fobj_path.get(fo, '?')))
        pending_irp[irp] = (ts, tid, pid, name, a)
    elif kind == 'sample':
        ip, tid = e[4:]
        pid = thread_pid.get(tid, -1)
        if pid not in focus or tid == 0: continue
        out.append({'ph': 'i', 's': 't', 'pid': pid, 'tid': tid, 'ts': us(ts), 'cat': 'sample',
                    'name': symbolize(ip, pid), 'args': {'ip': '0x%x' % ip}})
        last_sample[(tid, ts)] = len(out) - 1
        stats['samples'] += 1
    elif kind == 'stack':
        ets, spid, stid, frames = e[4:]
        i = last_sample.get((stid, ets))
        if i is None: continue
        # kernel and user parts of one sample arrive as two StackWalk events with the same timestamp
        a = out[i]['args']
        a['stack'] = a.get('stack', []) + [symbolize(fr, spid) for fr in frames]
        a['stack_leaf_kernel'] = next((f for f in a['stack'] if f.split('!')[0].split('+')[0] in ('nt', 'bfs', 'fltmgr', 'ntfs', 'luafv', 'wdfilter', 'fileinfo', 'wof')), '')
        a['stack_user_top'] = next((f for f in a['stack'] if '!' in f and not f.lower().startswith(('ntdll', 'kernelbase', 'kernel32')) and f.split('!')[0].split('+')[0] not in ('nt', 'bfs', 'fltmgr', 'ntfs', 'luafv', 'wdfilter', 'fileinfo', 'wof')), '')
    elif kind == 'process':
        t, p, img = e[4:]
        out.append({'ph': 'i', 's': 'p', 'pid': p, 'tid': 0, 'ts': us(ts), 'cat': 'process',
                    'name': '%s %s' % ('start' if t == 1 else 'end', img)})

if args.debug_stacks:
    for tid, st in pending_sys.items():
        if st and thread_pid.get(tid, -1) in focus:
            print('leftover', label(thread_pid.get(tid, -1)), tid, len(st), [symtab.get(a, hex(a)) for _, a in st[:12]])
# trailing sched slices up to the last event
tend = events[-1][0]
for cpu, (tid, sts) in cur.items():
    if tid:
        ppid = thread_pid.get(tid, -1)
        out.append({'ph': 'X', 'pid': CPU_PID, 'tid': CPU_PID + cpu, 'ts': us(sts), 'dur': us(tend) - us(sts),
                    'name': '%s %d' % (label(ppid), tid), 'cat': 'sched', 'args': {'pid': ppid, 'tid': tid}})

# phase annotation: the client's main thread issues the environment-creation RPC to AppInfo
# asynchronously and waits for its completion in NtWaitForSingleObject until the child exists.
cl = [pid for pid, n in proc_name.items() if n.lower() == 'bazelsandbox.exe']
starts = sorted(e['ts'] for e in out if e['ph'] == 'i' and e['cat'] == 'process' and e['name'].startswith('start'))
if cl:
    waits = [e for e in out if e['ph'] == 'X' and e['cat'] == 'syscall' and e['pid'] in cl
             and e['name'] in ('NtWaitForSingleObject', 'NtAlpcSendWaitReceivePort')
             and any(e['ts'] < st < e['ts'] + e['dur'] + 20000 for st in starts)]
    if waits:
        big = min(waits, key=lambda e: e['ts'])   # the first such wait precedes the child; later ones wait for it to exit
        out.append({'ph': 'b', 'cat': 'phase', 'id': 1, 'pid': big['pid'], 'ts': big['ts'],
                    'name': 'client waits for AppInfo: CreateProcessSecurityEnvironment RPC'})
        out.append({'ph': 'e', 'cat': 'phase', 'id': 1, 'pid': big['pid'], 'ts': big['ts'] + big['dur']})
        stats['env_create_wait_ms'] = round(big['dur'] / 1000, 1)
order = {}
for i, spec in enumerate(args.focus.split(',')):
    order[spec.split(':')[0].lower()] = i
for pid in sorted(set(thread_pid.values()) | set(proc_name)):
    if pid in focus or pid in seen_pids:
        out.append({'ph': 'M', 'name': 'process_name', 'pid': pid, 'args': {'name': '%s (pid %d)' % (label(pid), pid)}})
        out.append({'ph': 'M', 'name': 'process_sort_index', 'pid': pid,
                    'args': {'sort_index': order.get(proc_name.get(pid, '').lower(), 50)}})
for tid, name in thread_name.items():
    pid = thread_pid.get(tid, -1)
    if pid in focus:
        out.append({'ph': 'M', 'name': 'thread_name', 'pid': pid, 'tid': tid, 'args': {'name': name}})

doc = {'traceEvents': out, 'displayTimeUnit': 'ms',
       'metadata': {'source': args.etl, 'clock': 'QPC %.0f Hz, t0 = tick %d' % (args.qpc_hz, t0),
                    'focus': {pid: label(pid) for pid in sorted(focus)}}}
opener = gzip.open if args.out.endswith('.gz') else open
with opener(args.out, 'wt') as fh:
    json.dump(doc, fh, separators=(',', ':'))
print('focus:', {pid: label(pid) for pid in sorted(focus)})
print('events:', len(out), dict(stats), 'span %.1f ms' % ((tend - t0) * tick_us / 1000))
