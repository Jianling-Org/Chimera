from pathlib import Path
import datetime,hashlib,json,os,re,sys,subprocess
P=Path(__file__).resolve().parent
V=Path('/root/chimera-gcc-validation-578ab8321');S=V/'source'
COMMIT='578ab8321c0788ab8cba1ad24324f220e1e4a149'
BOOT='609feecc-71d1-4ada-a04f-d381df021435'

def sha(p):
 h=hashlib.sha256()
 with Path(p).open('rb') as f:
  for b in iter(lambda:f.read(4*1024**2),b''):h.update(b)
 return h.hexdigest()
def save(p,x):
 p=Path(p);t=p.with_name(p.name+'.new');t.write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');t.replace(p)
def require(x,msg):
 if not x:raise RuntimeError(msg)
def qualify(number):
 require(number in ['41','42'],'Unknown model protocol')
 N=P/('model'+number+'-attempt4');B=N;W=N/'workspaces'/('llama'+number)
 for name in ['build','check','prepare','controller']:
  resource=json.loads((N/(name+'.resources.json')).read_text())
  require([resource[k] for k in ['SERVICE_RESULT','EXIT_CODE','EXIT_STATUS']]==['success','exited','0'],'Actual '+name+' did not pass')
  events=dict(line.split() for line in resource['memory.events'].splitlines())
  require(resource['memory.swap.peak']=='0' and all(events[k]=='0' for k in ['oom','oom_kill','oom_group_kill']),'Swap/OOM in '+name)
 require(json.loads((N/'completion.json').read_text()).get('passed') is True,'Restoration incomplete')
 require(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==BOOT,'Boot changed')
 check=json.loads((N/'check.json').read_text());require(check.get('passed') is True and check['summary']['findings_total']==0,'Strict check failed')
 require(check['summary'].get('stack_object_plugin') is True,'Missing StackObject metadata')
 sys.path[:0]=[str(S/'cli'),str(S)]
 sys.meta_path[:]=[f for f in sys.meta_path if type(f).__name__!='ScikitBuildRedirectingFinder']
 from chimera.runtime.manifest import read_manifest
 from chimera.preprocess.offline.config import BaseConfig
 from chimera.runtime.validate import verify_workspace
 from chimera.workspace import verify_workspace_installation
 from chimera.runtime.launcher.run import _resolve_main,_precheck,_search_paths,resolved_module_paths,with_main_module,_run_loader,parse_loader_list
 from chimera.preprocess.offline.analysis.platform.linux.elf import interpreter
 native_library_path=str(N/'inputs')
 require(not os.environ.get('LD_PRELOAD'),'Unexpected qualifier preload')
 os.environ['LD_LIBRARY_PATH']=native_library_path
 settings=BaseConfig(data_root=N/'data',workspace_root=N/'workspaces',scalar_root=N/'native-scalar-base')
 verify_workspace_installation(W)
 # Keep the full host/artifact verification used by the previous qualifier.
 m=verify_workspace(W,settings)
 dependencies=json.loads((N/'dependency-bindings.json').read_text());require(dependencies.get('passed') is True,'Native dependency bindings not verified')
 for item in m.modules:
  if item.role=='dependency':
   row=dependencies['dependencies'][item.runtime_name]
   require(item.selected_kind=='original' and item.delivery=='target' and item.sha256==row['sha256'],'Dependency binding changed')
 main=next(x for x in m.modules if x.runtime_name=='llama-perplexity')
 require(main.sha256==sha(B/'inputs/llama-perplexity'),'Manifest ELF differs')
 props={}
 for item in m.variant_properties:
  if item.name=='vector_vlen_bits':props.setdefault(item.variant_id,{})[item.side]=int(item.value)
 routes={v.variant_id:[props[v.variant_id]['input'],props[v.variant_id]['output']] for v in m.variants if v.module_id==main.module_id}
 require({tuple(v) for v in routes.values()}=={(256,1024),(1024,256)},'Missing bidirectional routes')
 for item in m.artifacts:require(sha(W/item.path)==item.sha256,'Workspace artifact changed '+item.path)
 # Match bootstrap registry's native PT_INTERP branch, without publishing or
 # rewriting receipts. Legacy prepare_launch requires a package-delivered libc.
 program=(B/'inputs/llama-perplexity').resolve(strict=True)
 main=_resolve_main(program,m,W)
 native_interpreter=interpreter(program)
 require(native_interpreter,'Native bootstrap program has no PT_INTERP')
 loader=Path(native_interpreter).resolve(strict=True)
 loader_module=next(item for item in m.modules if item.runtime_name==Path(native_interpreter).name)
 require(loader_module.selected_kind=='original' and loader_module.delivery=='target' and sha(loader)==loader_module.sha256,'Native loader identity differs')
 resolved=_precheck(loader,program,_search_paths(W,program),m,W,main)
 native_rc,native_stdout,native_stderr=_run_loader(loader,('--list',str(program)))
 require(native_rc==0,'Declared native environment cannot resolve program: '+native_stderr)
 by_name={item.runtime_name:item for item in m.modules}
 loaded=[row for row in parse_loader_list(native_stdout) if row.path is not None]
 require(all(row.name in by_name for row in loaded),'Native loader reports unrecorded dependency')
 native_resolved=with_main_module({by_name[row.name].module_id:row.path for row in loaded},program,main)
 expected={item.module_id:item for item in m.modules}
 require(set(resolved)==set(expected) and set(native_resolved)==set(expected),'Unresolved native or Workspace module')
 for key,item in expected.items():
  require(resolved[key].resolve()==native_resolved[key].resolve(),'Native and Workspace library paths differ: '+item.runtime_name)
  require(sha(resolved[key])==item.sha256 and sha(native_resolved[key])==item.sha256,'Native library SHA differs: '+item.runtime_name)
 # Bind the actual loaded native files to the already published inode receipts.
 receipt_rows=[line.split('\t') for line in (W/'artifacts/verified-files.tsv').read_text().splitlines()]
 for key,item in expected.items():
  path=native_resolved[key];matches=[row for row in receipt_rows if Path(row[0]).resolve()==path.resolve() and row[1]==item.sha256]
  require(len(matches)==1,'Loaded native module missing from receipts: '+item.runtime_name)
  st=path.stat();identity=[st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns//10**9,st.st_mtime_ns%10**9,st.st_ctime_ns//10**9,st.st_ctime_ns%10**9]
  require(list(map(int,matches[0][2:]))==identity,'Loaded native module inode identity differs: '+item.runtime_name)
 resolution=dict(mode='bootstrap-native',environment={'LD_LIBRARY_PATH':native_library_path},loader=str(loader),loader_sha256=sha(loader),modules={key:dict(path=str(native_resolved[key].resolve()),sha256=sha(native_resolved[key])) for key in sorted(expected)},production_api_sha256={relative:sha(S/relative) for relative in ['cli/chimera/cli.py','runtime/launcher/run/chimera/launcher/run.py','runtime/launcher/preload/chimera/preload/registry.py','runtime/artifacts/validate/chimera/validate/workspace.py']})
 snapshot=json.loads((P/'startup-attempt1/inputs-before.json').read_text())
 bootstrap=V/'build/runtime/libchimera-bootstrap.so'
 require(sha(bootstrap)==snapshot['assets']['bootstrap']['sha256'],'Current bootstrap differs from audited startup')
 sys.path.insert(0,str(P/'model-suite-checkout-v7/experiments/runtime-evaluation'))
 import evaluation_common as common
 frozen=json.loads((P/'model-suite-v7-upload-sha256.json').read_text())
 require(all(sha(p)==h for p,h in frozen.items()),'Frozen model suite changed')
 example='llama-ppl2pct.example.json' if number=='41' else 'llama-scalar-ppl2pct.example.json'
 cfg=json.loads((P/'model-suite-checkout-v7/experiments/runtime-evaluation'/example).read_text())
 cfg.update(source_tree=str(S),source_commit=COMMIT,kernel='6.18.3-chimera-d02cd7352',environment={'OMP_DYNAMIC':'FALSE','OMP_PROC_BIND':'FALSE','LD_LIBRARY_PATH':native_library_path})
 model=Path('/root/yangzheng/chimera-e2e/v32-k3-check-20261017T001500Z-c05ba/source/examples/applications/llama-cpp/model/tinyllama-1.1b-chat-v1.0.Q3_K_S.gguf')
 paths={'bootstrap':bootstrap,'registry':N/'registry.tsv','profile':N/'profile.toml','elf':B/'inputs/llama-perplexity','model':model,'corpus':model.parent.parent/'prompt/file.txt','native_launcher':Path('/root/chimera-gcc-performance-578ab8321-20261029/bin/native-launch-image-v3')}
 paths['build_record']=B/'build-record.json'
 paths['input_qualifier']=Path(__file__).resolve()
 paths['check']=N/'check.json'
 paths['q8_native_parity']=P/'q8-zero-probe2/result.json'
 paths['q8_native_resources']=P/'q8-zero-probe2/unit.resources.json'
 paths['dependency_bindings']=N/'dependency-bindings.json'
 if number=='41':paths['preserved_failure_index']=P/'model41-attempt1-preservation-index.json'
 if number=='42':paths.update(scalar_control=N/'scalar-control.cmake',compile_commands=N/'build/compile_commands.json',source_build_record=B/'source-build-record.json')
 inventory=N/'llama-source-inputs.json'
 source=B/'llama-source'
 if inventory.exists():
  require(number=='41','Unexpected prior scalar source inventory')
  prior=json.loads((P/'model41-input-qualification.json').read_text())
  require(prior.get('passed') is True and sha(inventory)==prior['current_identities']['assets']['llama_source_inventory']['sha256'],'Existing source inventory identity differs')
  existing=json.loads(inventory.read_text());require(existing['root']==str(source),'Existing source inventory root differs');rows=existing['files']
 else:
  require(number=='42','Missing previously qualified model41 inventory')
  rows=[dict(path=p.relative_to(source).as_posix(),sha256=sha(p),symlink=os.readlink(p) if p.is_symlink() else None) for p in sorted(source.rglob('*')) if p.is_file() and '.git' not in p.relative_to(source).parts]
  save(inventory,dict(root=str(source),files=rows))
 paths['llama_source_inventory']=inventory;cfg['inventories']=['llama_source_inventory']
 paths['policy_authorization']=P/'model-policy-ppl2pct-v5-authorization-1.json'
 policy=json.loads(paths['policy_authorization'].read_text());require(policy['selected_preference']=='prefer-a100' and cfg['protocol'] in policy['protocols'],'New model policy not authorized')
 require(not any(key.startswith('LLAMA_ARG_') for key in os.environ),'Unexpected inherited application options')
 require(cfg.get('application_configuration')=='original-default' and 'diagnostic_configuration' not in cfg,'Wrong v5 application configuration')
 paths.update(prior_default_failure=P/'model41-runtime-events-v4-attempt1-preservation-index.json',prior_fa_off_timeout=P/'model41-fa-off-auto-preflight1-preservation-index.json',prior_fa_off_wait_timeout=P/'model41-fa-off-wait-diagnosis1-preservation-index.json')
 require(cfg.get('automatic_preference')=='prefer-a100','New protocol preference differs')
 require(policy['relative_ppl_tolerance']==cfg.get('relative_ppl_tolerance')==.02 and 'absolute_ppl_tolerance' not in cfg,'New PPL rule not authorized')
 native_proof=P/'model41-native-diagnosis1-independent-verification.json'
 native=json.loads(native_proof.read_text());require(native.get('passed') is True and sha(native['completion_path'])==native['completion_sha256'] and sha(native['result_path'])==native['result_sha256'],'Native comparison proof changed')
 paths['native_ppl_comparison']=native_proof
 paths.update(thread_layout=P/'model41-lifecycle-btf-layout1.json',readiness_contract=P/'model41-readiness-source-contract1.json',thread_evidence_preflight=P/'model41-lifecycle-preflight3-independent-verification.json')
 evidence=json.loads(paths['thread_evidence_preflight'].read_text());require(evidence.get('passed') is True and evidence.get('actual')=='success/exited/0' and evidence.get('all_commits_positive_kernel_predicate') is True,'Event evidence preflight not independently qualified')
 require(sha(evidence['completion_path'])==evidence['completion_sha256'] and sha(evidence['result_path'])==evidence['result_sha256'],'Event preflight bindings changed')
 import ast
 thread_source=P/'model-suite-checkout-v7/experiments/runtime-evaluation/model_thread_trace.py'
 nodes={node.name:hashlib.sha256(ast.dump(node,include_attributes=False).encode()).hexdigest() for node in ast.parse(thread_source.read_bytes()).body if isinstance(node,(ast.FunctionDef,ast.ClassDef))}
 # ast.dump's empty-list formatting changed between Python3.12 and3.13.
 # Compare both frozen sources in this same interpreter and pin the original
 # hardware preflight source bytes; retain the independently computed old hash.
 baseline=P/'model_thread_trace_candidate2.py'
 baseline_sha='1d84ad3b91a4fa54d002e9211ce21ad6eaefeddc1d79154e246f911bc66e0ea1'
 baseline_manifest=P/'model41-lifecycle-preflight3-frozen.json'
 baseline_frozen=json.loads(baseline_manifest.read_text())
 require(sha(baseline)==baseline_frozen[str(baseline)]==baseline_sha,'Hardware preflight source bytes changed')
 baseline_nodes={node.name:hashlib.sha256(ast.dump(node,include_attributes=False).encode()).hexdigest() for node in ast.parse(baseline.read_bytes()).body if isinstance(node,(ast.FunctionDef,ast.ClassDef))}
 require(all(nodes.get(name)==baseline_nodes.get(name) for name in evidence['backend_core_ast_sha256']),'Thread evidence core differs from frozen hardware preflight in same interpreter')
 paths.update(event_backend_preflight_source=baseline,event_backend_preflight_manifest=baseline_manifest,event_backend_ast_diagnosis=P/'model41-events-v4-core-ast-diagnosis1.json',event_qualification_failure=P/'model41-events-v4-qualification1-preservation-index.json')
 backend_binding=dict(python=sys.version,preflight_source_sha256=baseline_sha,preflight_manifest_sha256=sha(baseline_manifest),same_interpreter_core_ast_sha256={name:nodes[name] for name in evidence['backend_core_ast_sha256']},original_independent_core_ast_sha256=evidence['backend_core_ast_sha256'])
 require(cfg.get('thread_evidence')=='kernel-lifecycle-v2' and cfg['protocol'] in ['llama-retest-v5','llama-scalar-retest-v5'],'Wrong full event protocol')
 cfg['assets']={name:dict(path=str(path),sha256=sha(path)) for name,path in paths.items()}
 receipts=['workspace.json','artifacts/verified-files.tsv','artifacts/verified-variants.tsv','artifacts/verified-tables.tsv']
 cfg['workspaces']=[dict(path=str(W),receipt_rows=len((W/'artifacts/verified-files.tsv').read_text().splitlines()),sha256={p:sha(W/p) for p in receipts})]
 common.validate_config(cfg,'llama')
 identities=common.input_identities(cfg,'llama')
 require(identities['boot_id']==BOOT,'Current boot differs')
 output=P/('model'+number+'-ppl2pct-v5.json');require(not output.exists(),'Refuse replacing run config');save(output,cfg)
 proof=dict(event_backend_binding=backend_binding,passed=True,stage='prepared_inputs_only',automatic_preference='prefer-a100',relative_ppl_tolerance=.02,model_runtime_passed=False,config=str(output),config_sha256=sha(output),current_identities=identities,main_routes=routes,manifest_modules=len(m.modules),manifest_artifacts=len(m.artifacts),resolved_modules={k:str(v) for k,v in resolved.items()},bootstrap_resolution=resolution,source_files=len(rows),check_sha256=sha(N/'check.json'),restoration_completion_sha256=sha(N/'completion.json'),prepared_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
 save(P/('model'+number+'-ppl2pct-v5-input-qualification.json'),proof)
 print(json.dumps({k:v for k,v in proof.items() if k not in ['current_identities','resolved_modules']},indent=2))
if __name__=='__main__':qualify(sys.argv[1])
