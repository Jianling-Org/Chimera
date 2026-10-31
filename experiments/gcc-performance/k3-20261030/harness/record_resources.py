import json,os,sys,time
from pathlib import Path
P=Path('/root/chimera-gcc-performance-j16-578ab8321-20261030')
value={'recorded_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())}
for key in ('SERVICE_RESULT','EXIT_CODE','EXIT_STATUS'):value[key]=os.environ.get(key)
try:
    group=Path('/sys/fs/cgroup')/Path('/proc/self/cgroup').read_text().split('0::',1)[1].strip().lstrip('/')
    for name in ('memory.peak','memory.events','memory.swap.peak','memory.max','memory.swap.max'):
        if (group/name).is_file():value[name]=(group/name).read_text().strip()
except Exception as error:value['error']=repr(error)
(P/'results'/(sys.argv[1]+'.resources.json')).write_text(json.dumps(value,indent=2)+'\n')
