#!/usr/bin/env python3
"""A transient systemd timer checks only this task every two minutes."""
import json,shutil,subprocess,time
from pathlib import Path
r=Path('/root/chimera-gcc-validation-578ab8321')
if not (r/'state.json').exists():raise SystemExit(0)
state=json.loads((r/'state.json').read_text())
sample={'utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'phase':state.get('phase'),
        'status':state.get('status'),'free_bytes':shutil.disk_usage('/').free}
unit=state.get('active_unit','')
if state.get('status')=='running' and unit.startswith('chimera-gcc-'):
    properties=subprocess.run(['systemctl','show',unit,'-p','ActiveState','-p','SubState','-p','MemoryCurrent','-p','MemoryPeak','-p','MemorySwapCurrent'],capture_output=True,text=True)
    sample['unit']=unit;sample['properties']=properties.stdout
    if sample['free_bytes']<3*1024**3:
        (r/'DISK_GUARD_TRIGGERED.json').write_text(json.dumps(sample,indent=2))
        subprocess.run(['systemctl','stop',unit],check=False)
        sample['action']='Stopped only this task active phase: disk below 3 GiB'
with (r/'watchdog.jsonl').open('a') as f:f.write(json.dumps(sample)+'\n')
(r/'heartbeat-sample.json').write_text(json.dumps(sample,indent=2)+'\n')
