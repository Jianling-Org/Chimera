from pathlib import Path
import datetime,json,os,subprocess,sys,traceback,hashlib
P=Path(__file__).resolve().parent

def sha(path):
 h=hashlib.sha256()
 with Path(path).open('rb') as f:
  for b in iter(lambda:f.read(1024**2),b''):h.update(b)
 return h.hexdigest()
def save(path,value):
 p=Path(path);t=p.with_name(p.name+'.new');t.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');t.replace(p)
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def require(value,message):
 if not value:raise RuntimeError(message)
def resources(number):
 group=Path('/sys/fs/cgroup')/Path('/proc/self/cgroup').read_text().split('0::',1)[1].strip().lstrip('/')
 value={k:os.environ.get(k) for k in ['SERVICE_RESULT','EXIT_CODE','EXIT_STATUS']}
 value.update({k:(group/k).read_text().strip() for k in ['memory.peak','memory.swap.peak','memory.events','memory.max','memory.swap.max']})
 save(P/('model'+number+'-runtime-ppl2pct-v5-controller-1.resources.json'),value)
def main(number):
 require(number in ['41','42'],'Unknown protocol')
 code=P/'model-suite-checkout-v7/experiments/runtime-evaluation/run_llama_acceptance.py'
 config=P/('model'+number+'-ppl2pct-v5.json');out=P/('model'+number+'-runtime-ppl2pct-v5-attempt1')
 unit='chimera-model'+number+'-runtime-ppl2pct-v5-controller-1.service';rc=1
 try:
  proof=json.loads((P/('model'+number+'-ppl2pct-v5-input-qualification.json')).read_text())
  require(proof.get('passed') is True and sha(config)==proof['config_sha256'],'Prepared input qualification differs')
  require(proof.get('automatic_preference')=='prefer-a100' and json.loads(config.read_text()).get('automatic_preference')=='prefer-a100','Wrong v5 preference')
  cfg=json.loads(config.read_text())
  require(cfg.get('application_configuration')=='original-default' and 'diagnostic_configuration' not in cfg,'Wrong application configuration')
  require(proof.get('relative_ppl_tolerance')==cfg.get('relative_ppl_tolerance')==.02 and 'absolute_ppl_tolerance' not in cfg,'Wrong v5 PPL rule')
  require(cfg.get('thread_evidence')=='kernel-lifecycle-v2' and cfg['protocol']==('llama-retest-v5' if number=='41' else 'llama-scalar-retest-v5'),'Wrong full events protocol')
  frozen=json.loads((P/'model-suite-v7-upload-sha256.json').read_text())
  require(all(sha(path)==expected for path,expected in frozen.items()),'Frozen suite differs')
  require(not out.exists(),'Refuse repeat runtime attempt')
  save(P/'state.json',dict(phase='running_model'+number+'_ppl2pct_v5',controller=unit,output=str(out),config=str(config),updated_utc=utc()))
  env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PYTHONUNBUFFERED='1',LC_ALL='C')
  for key in ['LD_PRELOAD','CHIMERA_BOOTSTRAP','CHIMERA_REGISTRY','CHIMERA_LAUNCH_PID','CHIMERA_AUTOMIGRATE']:env.pop(key,None)
  with (P/('model'+number+'-runtime-ppl2pct-v5-launcher-1.log')).open('wb') as log:
   result=subprocess.run([sys.executable,'-B',str(code),'--config',str(config),'--output',str(out),'--run'],env=env,stdout=log,stderr=subprocess.STDOUT)
  completion=json.loads((out/'completion.json').read_text()) if (out/'completion.json').exists() else {}
  require(result.returncode==0 and completion.get('passed') is True,'Actual model suite failed')
  save(P/('model'+number+'-runtime-ppl2pct-v5-controller-1.result.json'),dict(passed=True,runner_returncode=result.returncode,completion=completion,ended_utc=utc()))
  save(P/'state.json',dict(phase='model'+number+'_ppl2pct_v5_runtime_complete_audit_pending',controller=unit,output=str(out),independent_audit_complete=False,updated_utc=utc()))
  rc=0
 except BaseException:
  save(P/('model'+number+'-runtime-ppl2pct-v5-controller-1.failure.json'),dict(passed=False,traceback=traceback.format_exc(),output=str(out),updated_utc=utc()))
  save(P/'state.json',dict(phase='model'+number+'_ppl2pct_v5_runtime_failed',controller=unit,output=str(out),updated_utc=utc()))
 finally:
  save(P/('model'+number+'-runtime-ppl2pct-v5-controller-1.exit.json'),dict(returncode=rc,updated_utc=utc()))
 if rc:raise SystemExit(rc)
if __name__=='__main__':
 if len(sys.argv)==3 and sys.argv[1]=='--resources':resources(sys.argv[2])
 else:main(sys.argv[1])
