import sys
from datetime import datetime

wake_times=[]
try:
    with open('/Users/aadmin/Desktop/assess/wake_events.txt') as f:
        for line in f:
            try:
                parts=line.strip().split()
                if len(parts)>=2:
                    dt=datetime.strptime(parts[0]+' '+parts[1],'%Y-%m-%d %H:%M:%S.%f')
                    wake_times.append(dt)
            except: pass
except: pass

xprotect_times=[]
try:
    with open('/Users/aadmin/Desktop/assess/xprotect_timeline.txt') as f:
        for line in f:
            try:
                parts=line.strip().split(None,1)
                if len(parts)==2:
                    minute=parts[1][:16]
                    dt=datetime.strptime(minute,'%Y-%m-%d %H:%M')
                    xprotect_times.append(dt)
            except: pass
except: pass

matches=[]
for xt in xprotect_times:
    for wt in wake_times:
        delta=abs((wt-xt).total_seconds())
        if delta<=300:
            matches.append({'xprotect':xt,'wake':wt,'gap_sec':delta})

print(f'Correlations found: {len(matches)}')
if matches:
    print('Top 10 closest:')
    for m in sorted(matches,key=lambda x:x['gap_sec'])[:10]:
        print(f'{m["xprotect"]} <-> {m["wake"]} Δ={m["gap_sec"]:.1f}s')
