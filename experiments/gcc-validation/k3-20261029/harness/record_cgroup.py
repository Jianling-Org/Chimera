#!/usr/bin/env python3
import json,os,sys,time
from pathlib import Path
r=Path('/root/chimera-gcc-validation-578ab8321')
value={'recorded_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())}
for key in ('SERVICE_RESULT','EXIT_CODE','EXIT_STATUS'):value[key]=os.environ.get(key)
try:
    group=Path('/sys/fs/cgroup')/Path('/proc/self/cgroup').read_text().split('0::',1)[1].strip().lstrip('/')
    for name in ('memory.peak','memory.events','memory.swap.peak','memory.max','memory.swap.max'):
        if (group/name).is_file():value[name]=(group/name).read_text().strip()
except Exception as e:value['error']=repr(e)
(r/'stage-results').mkdir(exist_ok=True)
(r/'stage-results'/(sys.argv[1]+'.resources.json')).write_text(json.dumps(value,indent=2)+'\n')
