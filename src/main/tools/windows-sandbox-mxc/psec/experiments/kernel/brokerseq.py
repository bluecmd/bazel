import gzip, json, sys, collections
d = json.load(gzip.open(sys.argv[1], 'rt')); ev = d['traceEvents']
X = [e for e in ev if e['ph'] == 'X']
bt = collections.Counter(e['tid'] for e in X if e['pid']==4344 and e['cat']=='syscall')
print('broker threads by syscalls:', bt.most_common(4))
tid = bt.most_common(1)[0][0]
t0 = float(sys.argv[2]) * 1000
seq = sorted([e for e in X if e['pid']==4344 and e['tid']==tid and e['cat'] in ('syscall','fileio') and t0 <= e['ts'] <= t0+float(sys.argv[3])*1000], key=lambda e: (e['ts'], -e['dur']))
for e in seq: print('   %9.1f %7.1f us %-7s %s %s' % (e['ts'], e['dur'], e['cat'], e['name'][:100], e['args'].get('status','') if e['cat']=='syscall' else (e['args'].get('create_options','') + ' ' + e['args'].get('status',''))))
# per-path counts over the broker burst 200..480 ms
burst = [e for e in X if e['pid']==4344 and e['tid']==tid and e['cat']=='syscall' and 200000 <= e['ts'] <= 480000]
c = collections.Counter(e['name'] for e in burst); s = collections.Counter()
for e in burst: s[e['name']] += e['dur']
print('broker main thread 200-480 ms, per syscall: count, total ms, per-path count (300 paths)')
for n, k in c.most_common(14): print('   %-32s %6d %8.1f ms  %.1f/path' % (n, k, s[n]/1000, k/300))
print('   total syscall time %.1f ms of %.1f ms' % (sum(s.values())/1000, 280))
sysw = [e for e in X if e['pid']==4 and e['cat']=='fileio' and 200000 <= e['ts'] <= 480000]
print('System fileio 200-480:', collections.Counter(e['name'].split(' ')[0] for e in sysw).most_common(5), 'sum %.1f ms' % (sum(e['dur'] for e in sysw)/1000))
print('System fileio paths:', collections.Counter(e['name'].split(' ',1)[1][:70] for e in sysw).most_common(3))
cw = [e for e in ev if e['ph'] in ('s','f')]
print('flows:', [(e['ph'], e['pid'], e['tid'], round(e['ts']/1000,1)) for e in cw[:12]])
