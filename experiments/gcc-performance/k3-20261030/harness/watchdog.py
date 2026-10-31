import json,shutil,subprocess,time
from pathlib import Path
P=Path('/root/chimera-gcc-performance-j16-578ab8321-20261030')
s=json.loads((P/'state.json').read_text()) if (P/'state.json').exists() else {}
sample={'utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'free_bytes':shutil.disk_usage(P).free,'state':s}
unit=s.get('active_unit','')
if s.get('status')=='running' and unit.startswith('chimera-gcc-j16-') and sample['free_bytes']<3*1024**3:
    sample['action']='stop only current performance phase below unchanged3GiB emergency threshold'
    (P/'disk-stop.json').write_text(json.dumps(sample,indent=2)+'\n')
    subprocess.run(['systemctl','stop',unit],check=False)
with (P/'watchdog.jsonl').open('a') as stream:stream.write(json.dumps(sample)+'\n')
(P/'watchdog-latest.json').write_text(json.dumps(sample,indent=2)+'\n')
