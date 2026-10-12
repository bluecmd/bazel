import gzip, json, sys, collections
d = json.load(gzip.open(sys.argv[1], 'rt')); ev = d['traceEvents']
X = [e for e in ev if e['ph'] == 'X']
names = {e['pid']: e['args']['name'] for e in ev if e['ph']=='M' and e['name']=='process_name'}
print('process events:', [(e['name'], round(e['ts']/1000,1)) for e in ev if e['ph']=='i' and e['cat']=='process'])
# client long top-level syscalls
cl = sorted([e for e in X if e['pid']==3552 and e['cat']=='syscall' and e['dur']>2000], key=lambda e: e['ts'])
print('client syscalls >2ms:'); [print('  tid %d %-32s ts %9.1f dur %8.1f ms' % (e['tid'], e['name'], e['ts']/1000, e['dur']/1000)) for e in cl[:25]]
# first/last client IOCTL and CreateFile burst
io = sorted([e for e in X if e['pid']==3552 and e['cat']=='syscall' and e['name'] in ('NtDeviceIoControlFile',)], key=lambda e: e['ts'])
print('client IOCTLs: n=%d first %.1f last %.1f ms' % (len(io), io[0]['ts']/1000, io[-1]['ts']/1000))
br = sorted([e for e in X if e['pid']==4344 and e['cat']=='syscall' and e['name'] in ('NtDeviceIoControlFile',)], key=lambda e: e['ts'])
print('broker IOCTLs: n=%d first %.1f last %.1f ms' % (len(br), br[0]['ts']/1000, br[-1]['ts']/1000))
# CPU time per process per 50 ms bucket
sched = [e for e in X if e['cat']=='sched']
B = 50000
buckets = collections.defaultdict(lambda: collections.Counter())
for e in sched:
    t = e['ts']; end = t + e['dur']
    while t < end:
        b = int(t // B); nxt = min(end, (b+1)*B)
        buckets[b][e['name'].rsplit(' ',1)[0]] += nxt - t; t = nxt
print('CPU ms per 50 ms bucket (2 CPUs):')
for b in sorted(buckets):
    c = buckets[b]
    print('  %5d-%5d ms  %s' % (b*50, b*50+50, '  '.join('%s=%.1f' % (k[:14], v/1000) for k, v in c.most_common(4))))
# per-path broker sequence: syscalls of the busiest broker thread in one 2 ms window in the middle of the burst
bt = collections.Counter(e['tid'] for e in X if e['pid']==4344 and e['cat']=='syscall')
tid = bt.most_common(1)[0][0]
mid = (br[0]['ts'] + br[-1]['ts']) / 2
seq = sorted([e for e in X if e['pid']==4344 and e['tid']==tid and e['cat']=='syscall' and mid <= e['ts'] <= mid+1500], key=lambda e: e['ts'])
print('broker thread %d, 1.5 ms slice at %.1f ms:' % (tid, mid/1000))
for e in seq: print('   %9.1f %7.1f us %s %s' % (e['ts'], e['dur'], e['name'], e['args'].get('status','')))
fio = sorted([e for e in X if e['pid']==4344 and e['tid']==tid and e['cat']=='fileio' and mid <= e['ts'] <= mid+1500], key=lambda e: e['ts'])
for e in fio: print('   %9.1f %7.1f us   FILE %s %s' % (e['ts'], e['dur'], e['name'][:90], e['args'].get('status','')))
# nttest: one open with nested zw calls
nt = sorted([e for e in X if e['pid']==4240 and e['name']=='NtCreateFile' and 200 < e['dur'] < 260], key=lambda e: e['ts'])
e0 = nt[len(nt)//2]
inner = sorted([e for e in X if e['pid']==4240 and e['tid']==e0['tid'] and e0['ts'] <= e['ts'] <= e0['ts']+e0['dur']], key=lambda e: e['ts'])
print('one sandboxed NtCreateFile in nttest (%.1f us):' % e0['dur'])
for e in inner: print('   +%6.1f %7.1f us %-8s %s %s' % (e['ts']-e0['ts'], e['dur'], e['cat'], e['name'][:80], e['args'].get('status','')))
