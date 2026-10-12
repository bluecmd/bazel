import sys, struct, collections, bisect
sys.path.insert(0, sys.argv[2])
import etl.etl as etl
from etl.etl import ChunkParser
PID = int(sys.argv[3])
f = etl.build_from_stream(open(sys.argv[1], 'rb').read())
imgs = []  # (base, size, name)
samples = {}  # (tid, ts) -> frames
stacks = []
def wstr(b, off):
    e = off
    while e + 1 < len(b) and b[e:e+2] != b'\0\0': e += 2
    return b[off:e].decode('utf-16-le', 'replace')
for ch in f.chunks:
    for ev in ChunkParser.parse(ch.payload):
        v = ev.value
        if ev.type == 'PerfInfoTraceRecord':
            g = str(v.header.group); t = v.header.type; b = bytes(v.mof_data)
            if (g == 'EVENT_TRACE_GROUP_IMAGE' and t in (3, 10)) or (g == 'EVENT_TRACE_GROUP_PROCESS' and t == 10):
                base, size, pid = struct.unpack_from('<QQI', b, 0)
                if pid == PID: imgs.append((base, size, wstr(b, 56)))
            elif g == 'EVENT_TRACE_GROUP_STACKWALK' and t == 32:
                ets, spid, stid = struct.unpack_from('<QII', b, 0)
                if spid == PID:
                    n = (len(b) - 16) // 8
                    stacks.append((stid, ets, struct.unpack_from('<%dQ' % n, b, 16)))
        elif ev.type == 'SystemTraceRecord':
            h = v.system_header
            if (str(h.header.group) == 'EVENT_TRACE_GROUP_IMAGE' and h.header.type in (3, 10)) or (str(h.header.group) == 'EVENT_TRACE_GROUP_PROCESS' and h.header.type == 10):
                b = bytes(v.mof_data); base, size, pid = struct.unpack_from('<QQI', b, 0)
                if pid == PID: imgs.append((base, size, wstr(b, 56)))
imgs = sorted(set(imgs)); print('images for pid', PID, len(imgs))
bases = [i[0] for i in imgs]
def sym(a):
    i = bisect.bisect_right(bases, a) - 1
    if i >= 0 and a < imgs[i][0] + imgs[i][1]:
        return '%s+0x%x' % (imgs[i][2].rsplit('\\', 1)[-1], a - imgs[i][0])
    return 'k' if a >= 0x800000000000 else '0x%x' % a
# merge kernel+user halves
merged = collections.defaultdict(list)
for tid, ets, fr in stacks: merged[(tid, ets)] += list(fr)
print('samples with stacks', len(merged))
mods = collections.Counter(); leafu = collections.Counter(); chains = collections.Counter(); callers_of_ntdll = collections.Counter()
for k, fr in merged.items():
    u = [sym(a) for a in fr if a < 0x800000000000]
    if not u: continue
    for m in set(x.split('+')[0] for x in u): mods[m] += 1
    leafu[u[0]] += 1
    # first non-ntdll/kernelbase frame = who asked
    for i, x in enumerate(u):
        if not x.lower().startswith(('ntdll', 'kernelbase', 'kernel32')):
            chains[' <- '.join(u[i:i+5])] += 1
            callers_of_ntdll[x] += 1
            break
print('modules in broker stacks (inclusive):', mods.most_common(15))
print('user leaf:', leafu.most_common(10))
print('first non-ntdll frame:', callers_of_ntdll.most_common(15))
print('chains:')
for c, n in chains.most_common(12): print('  %3d %s' % (n, c))
