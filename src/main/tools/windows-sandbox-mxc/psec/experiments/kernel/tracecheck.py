import gzip, json, sys, collections, statistics
d = json.load(gzip.open(sys.argv[1], 'rt'))
ev = d['traceEvents']
by = collections.defaultdict(list)
for e in ev:
    if e['ph'] == 'X' and e['cat'] != 'zwcall': by[(e['pid'], e['tid'], e['cat'])].append(e)
names = {e['pid']: e['args']['name'] for e in ev if e['ph']=='M' and e['name']=='process_name'}
# syscall durations per process
for pid in (4240, 3552, 4344, 4):
    sc = [e for (p,t,c),l in by.items() if p==pid and c=='syscall' for e in l]
    cnt = collections.Counter(e['name'] for e in sc)
    print(names.get(pid), 'syscalls', len(sc), cnt.most_common(8))
    for n in ('NtCreateFile','NtOpenFile','NtAlpcSendWaitReceivePort','NtDeviceIoControlFile','NtQueryFullAttributesFile','NtClose'):
        ds = sorted(e['dur'] for e in sc if e['name']==n)
        if ds: print('   %-28s n=%5d median=%8.1f p90=%8.1f max=%10.1f sum=%10.1f us' % (n, len(ds), statistics.median(ds), ds[int(len(ds)*.9)], ds[-1], sum(ds)))
# containment check: fileio Create inside a syscall of the same tid
ins = tot = 0
for (p,t,c), l in by.items():
    if c != 'fileio': continue
    sys_ = sorted(by.get((p,t,'syscall'), []), key=lambda e: e['ts'])
    starts = [e['ts'] for e in sys_]
    import bisect
    for e in l:
        if not e['name'].startswith('Create'): continue
        tot += 1
        i = bisect.bisect_right(starts, e['ts']) - 1
        if i >= 0 and sys_[i]['ts'] + sys_[i]['dur'] >= e['ts'] + e['dur'] - 0.2: ins += 1
print('fileio Create inside same-thread syscall: %d/%d' % (ins, tot))
# the big ALPC wait of the client
cl = [e for (p,t,c),l in by.items() if p==3552 and c=='syscall' for e in l if e['name']=='NtAlpcSendWaitReceivePort']
cl.sort(key=lambda e: -e['dur'])
for e in cl[:3]: print('client ALPC', e['tid'], 'ts', e['ts'], 'dur', e['dur'])
big = cl[0]
# broker activity during it
br = [e for (p,t,c),l in by.items() if p==4344 and c=='syscall' for e in l if big['ts'] <= e['ts'] <= big['ts']+big['dur']]
print('broker syscalls during client wait:', len(br), collections.Counter(e['name'] for e in br).most_common(10))
sched = [e for e in ev if e['ph']=='X' and e['cat']=='sched' and big['ts'] <= e['ts'] <= big['ts']+big['dur']]
cpu = collections.Counter()
for e in sched: cpu[e['name'].rsplit(' ',1)[0]] += e['dur']
print('CPU time during client wait (ms):', [(k, round(v/1000,1)) for k,v in cpu.most_common(6)])
fio = [e for (p,t,c),l in by.items() if p==4344 and c=='fileio' for e in l if big['ts'] <= e['ts'] <= big['ts']+big['dur']]
print('broker fileio during wait:', collections.Counter(e['name'].split(' ')[0] for e in fio).most_common(8))
sysio = [e for (p,t,c),l in by.items() if p==4 and c=='fileio' for e in l if big['ts'] <= e['ts'] <= big['ts']+big['dur']]
print('System fileio during wait:', collections.Counter(e['name'].split(' ')[0] for e in sysio).most_common(8))
print('samples by leaf in broker:', collections.Counter(e['name'].split('+')[0] for e in ev if e['ph']=='i' and e['cat']=='sample' and e['pid']==4344).most_common(10))
print('samples by leaf in nttest:', collections.Counter(e['name'].split('+')[0] for e in ev if e['ph']=='i' and e['cat']=='sample' and e['pid']==4240).most_common(10))
print('flows:', sum(1 for e in ev if e['ph']=='s'), sum(1 for e in ev if e['ph']=='f'))
