"""Publish a Chinese performance report only after the independent audit exits 0."""
from pathlib import Path
import collections, datetime, hashlib, json, statistics

P=Path('/root/chimera-gcc-performance-j16-578ab8321-20261030')
A=P/'audits/final-1'
def load(p):return json.loads(Path(p).read_text())
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def write(p,x):Path(p).write_text(x,encoding='utf-8')
def actual(name):
    result=load(P/'results'/(name+'.json'));resources=load(P/'results'/(name+'.resources.json'))
    assert result['passed'] and result['rc']==0
    assert [resources[k] for k in ('SERVICE_RESULT','EXIT_CODE','EXIT_STATUS')]==['success','exited','0']
    return result,resources

def main():
    audit,resource=actual('final-audit-1'); actual('controller-2')
    assert audit['rounds']==108 and audit['measured_rounds']==89 and audit['warmups']==19
    assert sha(P/'final_audit_j16_1.py')==audit['audit_source_sha256']
    assert sha(A/'evidence-sha256.json')==audit['evidence_manifest_sha256']
    groups=load(A/'statistics.json');rows=load(A/'rounds.json')
    assert groups==audit['statistics'] and len(rows)==108
    by={(x['kind'],x['workers'],x['mode']):x for x in groups}
    modes=('x100','auto-x100','auto-a100','static16')
    labels={'x100':'原生 X100（不迁移）','auto-x100':'自动 prefer-x100','auto-a100':'自动 prefer-a100','static16':'静态分簇（不迁移）'}
    units=[];images=[]
    for x in groups:
        base=by[(x['kind'],x['workers'] if x['kind']=='units' else 16,'x100')]['median_seconds']
        row=dict(x,time_reduction_percent=(1-x['median_seconds']/base)*100,speedup_vs_native=base/x['median_seconds'])
        (units if x['kind']=='units' else images).append(row)
    aggregate=[]
    for kind in ('units','image'):
        for mode in modes:
            selected=[r for r in rows if r['measured'] and r['kind']==kind and r['mode']==mode]
            if not selected:continue
            health=collections.Counter();logs=collections.Counter();cpus=collections.Counter();moves=collections.Counter()
            for r in selected:
                health.update(r['health']['counts']);logs.update(r['kernel']['known_log_counts'])
                cpus.update(r['metrics']['cc1_cluster_observations']);moves.update(r['migration_deltas'])
            aggregate.append(dict(kind=kind,mode=mode,rounds=len(selected),health_samples=dict(health),known_kernel_logs=dict(logs),cc1_cluster_observations=dict(cpus),migration_deltas=dict(moves),max_sample_gap_seconds=max(r['metrics']['max_sample_gap_seconds'] for r in selected)))
    summary=dict(status='passed_conditional',scope='assume-scalar-independent',commit=audit['commit'],kernel=audit['kernel'],image_all_groups_make_jobs=16,native_cpu_mask="0-7",unit_rounds=96,image_rounds=12,measured_rounds=89,warmups=19,unit_statistics=units,image_statistics=images,measured_environment=aggregate,audit_actual_exit='success/exited/0',audit_peak_bytes=int(resource['memory.peak']),audit_sha256=sha(P/'results/final-audit-1.json'),audit_evidence_manifest_sha256=audit['evidence_manifest_sha256'],canonical=load(P/'artifacts/canonical-image-j16/hashes.json'),preflights=audit['preflights'],completed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
    out=P/'performance-summary-j16.json';report=P/'同16并发性能报告.zh-CN.md';assert not out.exists() and not report.exists()
    write(out,json.dumps(summary,ensure_ascii=False,indent=2)+'\n')
    image_map={r['mode']:r for r in images}; native=image_map['x100']; ax=image_map['auto-x100'];aa=image_map['auto-a100']
    lines=['# K3 GCC 同16并发性能对照报告','',
      '结论：在本机固定环境与 `assume-scalar-independent` 条件范围内，有效性能套件全部完成并通过独立审计。完整 Image 构建的中位耗时：原生 {:.3f} 秒，prefer-x100 {:.3f} 秒，prefer-a100 {:.3f} 秒。'.format(native['median_seconds'],ax['median_seconds'],aa['median_seconds']),'',
      '相对原生组，prefer-x100 耗时减少 {:.2f}%（吞吐比 {:.3f}×），prefer-a100 耗时减少 {:.2f}%（吞吐比 {:.3f}×）。三组全部为 -j16；原生16个编译任务仅用X100的8核，两个自动组可跨两簇共16核。收益包含核心扩展、放置策略及运行时成本；不能全部归因于一次迁移操作。'.format(ax['time_reduction_percent'],ax['speedup_vs_native'],aa['time_reduction_percent'],aa['speedup_vs_native']),'',
      'prefer-x100 的 Image 中位耗时比 prefer-a100 低 {:.2f}%。以下同并发与静态分簇对照用于进一步观察策略成本。'.format((1-ax['median_seconds']/aa['median_seconds'])*100),'',
      '## 完整 Image：3 次正式测量/组','',
      '| 组别 | 并发 | 三次原始耗时（秒） | 中位数（秒） | 最小–最大（秒） | 相对原生吞吐比 | 耗时减少 |',
      '|---|---:|---|---:|---|---:|---:|']
    for mode in modes[:3]:
        x=image_map[mode];lines.append('| {} | {} | {} | {:.3f} | {:.3f}–{:.3f} | {:.3f}× | {:.2f}% |'.format(labels[mode],x['workers'],', '.join(f'{v:.6f}' for v in x['raw_seconds']),x['median_seconds'],x['min_seconds'],x['max_seconds'],x['speedup_vs_native'],x['time_reduction_percent']))
    lines+=['','吞吐比 = 原生组中位耗时 ÷ 本组中位耗时；耗时减少 = 1 − 本组中位耗时 ÷ 原生组中位耗时。Image 吞吐单位为完整构建/秒。','',
      '## 相同并发：每轮相同的 64 个真实 Kbuild C 编译任务','',
      '每个并发点与组别分别有 1 次预热、5 次正式测量。静态分簇按固定 worker 槽位交替放到 X100/A100，共享任务队列；并发 1 时只有一个 X100 worker，并发 8 时为 4+4，并发 16 时为 8+8，并发 24 时为 12+12。原生组始终使用 X100 的 8 个 CPU。','',
      '| 并发 | 组别 | 五次原始耗时（秒） | 中位数（秒） | 最小–最大（秒） | 任务/秒 | 同并发原生吞吐比 |',
      '|---:|---|---|---:|---|---:|---:|']
    for workers in (1,8,16,24):
        for mode in modes:
            x=next(x for x in units if x['workers']==workers and x['mode']==mode)
            lines.append('| {} | {} | {} | {:.3f} | {:.3f}–{:.3f} | {:.3f} | {:.3f}× |'.format(workers,labels[mode],', '.join(f'{v:.6f}' for v in x['raw_seconds']),x['median_seconds'],x['min_seconds'],x['max_seconds'],x['throughput_per_second'],x['speedup_vs_native']))
    lines+=['','### 自动组相对静态分簇','',
      '| 并发 | prefer-x100 / 静态吞吐比 | prefer-a100 / 静态吞吐比 | prefer-x100 / prefer-a100 吞吐比 |',
      '|---:|---:|---:|---:|']
    for w in (1,8,16,24):
        s=by[('units',w,'static16')]['median_seconds'];x=by[('units',w,'auto-x100')]['median_seconds'];a=by[('units',w,'auto-a100')]['median_seconds']
        lines.append(f'| {w} | {s/x:.3f}× | {s/a:.3f}× | {a/x:.3f}× |')
    lines+=['','这些是同一任务集合的整批吞吐对照。静态组与自动组的放置方式、运行时开销、任务分配和迁移共同影响结果；该对照不能单独测出一次迁移的延迟。','',
      '## 实际执行与迁移旁证','',
      '正式计时关闭详细 debug/kprobe，所有组统一进行约 0.5 秒周期的 CPU、温度、频率与内存采样。原始指标字节 SHA、样本数与摘要已重新核对。下面 CPU 分簇数是 cc1 的离散观测点数量，不是 CPU 时间占比。迁移数是计时窗口前后的内核已提交计数增量；逐 TID 的 ACK/CPU 证明来自独立预检。','',
      '| 工作负载 | 组别 | cc1 在 X100/A100 的观测点 | 256→1024 提交增量 | 1024→256 提交增量 |',
      '|---|---|---|---:|---:|']
    for x in aggregate:
        c=x['cc1_cluster_observations'];m=x['migration_deltas']
        lines.append('| {} | {} | {} / {} | {} | {} |'.format(x['kind'],labels[x['mode']],c.get('x100',0),c.get('a100',0),m.get('prefer_a100_x100_to_a100_migrations',0),m.get('prefer_a100_a100_to_x100_migrations',0)))
    for attempt,pf in audit['preflights'].items():
        lines+=['','预检 {}：8 组、128 条真实 xgcc→exec cc1 编译链，实际初始化与每 exec 就绪、原始 action=1/return=8 ACK 和实际 CPU 提交已重放，数值参考与所有对象 SHA 一致；未注册 as 保持严格 unready 且无跨 VLEN 提交。双向 cc1 提交为：prefer-x100 {}，prefer-a100 {}。'.format(attempt,pf['routes']['auto-x100'],pf['routes']['auto-a100'])]
    lines+=['','## 存储维护与环境限制','',
      '用户授权将实际 BKOPS 0/1/2，以及精确 priority=3、控制器 c0e00000.ufshc、ufshcd_bkops_exception_event_handler 的 status 1/2 维护消息单列保留。全部原始字节、时间、序号、等级、SHA 与次数均保留；状态 3、未知状态、critical health 非零、I/O 错误、其他未知内核告警仍失败。未修改驱动、设备、电源或日志级别。','',
      '| 正式测量集合 | 组别 | BKOPS 0/1/2 健康采样数 | 精确 status 1/2 内核消息数 |',
      '|---|---|---|---|']
    for x in aggregate:
        h=x['health_samples'];k=x['known_kernel_logs'];lines.append('| {} | {} | {} / {} / {} | {} / {} |'.format(x['kind'],labels[x['mode']],h.get('0',0),h.get('1',0),h.get('2',0),k.get('1',0),k.get('2',0)))
    all_h=collections.Counter();all_k=collections.Counter()
    for r in rows:all_h.update(r['health']['counts']);all_k.update(r['kernel']['known_log_counts'])
    lines+=['','包含预热的完整 108 轮共保留健康采样 {} 条（BKOPS 0/1/2 = {}/{}/{}），精确维护日志 status 1/2 = {}/{}。critical health 全部为 0，未知内核告警与日志序号缺失为 0。健康状态约每 30 秒只读采样，并在边界额外采样；不能从离散观测推断状态 2 的持续时长或具体性能损失，所报成绩包含本机当时的存储环境影响。'.format(sum(all_h.values()),all_h['0'],all_h['1'],all_h['2'],all_k['1'],all_k['2']),'',
      'CPU 频率维持 userspace 配置：X100 2.2GHz、A100 1.8GHz，未作调频或电源更改。两套工作负载各在 130 秒空闲后冻结 7 个温度传感器基线，每轮起始温度均在相应基线 +3°C 上限内；正式采样频率记录及当前 governor/min/max/setspeed 均已核对。','',
      '## 计时、资源和正确性','',
      '- 全部 108 轮均有真实 systemd success/exited/0、资源与 time 记录。各轮 OOM/oom_kill=0、swap 峰值=0，九项迁移账本均在边界归零，无新增迁移超时。',
      '- 成绩取内部 CLOCK_MONOTONIC 的编译窗口，包含编译器启动、bootstrap 和迁移；准备、SHA 校验、冷却在窗口外。外层 time -v 含这些额外阶段，其墙钟不作为成绩。',
      '- 每轮 Image 实际分配至少 12GiB 工作容量探针后，仍有至少 6GiB 空闲；12GiB cgroup 上限、10GiB MemoryHigh、0 swap、有限 4 小时单轮时限。',
      '- 各轮都使用固定源码、公共 config 与确定的构建元数据；64 个任务、当前 seed 对象及全部 Image 记录均与原生 SHA 一致。保留的 canonical Image/vmlinux/System.map/config 已独立重算 SHA。成功轮的自有中间文件已在当时逐项比对后删除；本次复核其原始记录与保留 canonical，不声称重新读取已经删除的中间文件。','',
      '| Canonical 工件 | SHA256 |','|---|---|']
    for name,digest in summary['canonical'].items():lines.append(f'| {name} | `{digest}` |')
    lines+=['','## 固定身份与条件范围','',
      '- Chimera：dev/automigration-subprocess，提交 `'+audit['commit']+'`。',
      '- 运行内核：`'+audit['kernel']+'`；隔离内核源码 HEAD `d02cd73523ab4c7e7e952969b8d2a95925ae64d9` 加原始 730 字节 BSP 补丁。当前整棵源码逐文件与原 git archive 加补丁对比通过。',
      '- xgcc/cc1、bootstrap、Profile、registry、两个 Workspace 的所有工件、78 行当前 receipt 内容与文件身份、variant/table 语义及原生完整表校验通过；没有重发凭据，也没有使用旧 gate 名单替代本轮证据。',
      '- 结论受 `assume-scalar-independent` 与已授权存储维护范围约束；不扩大原静态检查条件，不等同于无条件生产安全或所有程序的性能结论。','',
      '## 协议修正与原失败保留','',
      '有效套件由保留的单元v2的96轮和全新同16并发i5 Image的12轮组成，分别统计。旧 Image 自动组在 Kbuild 编译器识别时，被 Runtime 可选 parent_thread_id stdout 通知污染，真实 exit=1 的旧 controller2、失败树和日志保留。Image v3 仅省略 CHIMERA_LAUNCH_PID 通知变量，不过滤编译器输出；生产 Runtime/GCC/内核/Profile/registry/初始化/继承/每 exec ready 与迁移处理器不变。12 个 Kbuild 输出探针、14 项边界回归和身份一致的原PF1/PF3真实128链ready/双向ACK+CPU证据再次重放通过。单元 v2 直接执行保存的 -c 命令，未受 Kbuild 版本解析问题影响；旧 Image 预热 1064.498 秒与失败组时长均未并入本报告。','',
      '旧 attempt1 因当时未获授权的实际 BKOPS=2 停止，原失败与全部证据保留；没有与本套件池化。第一次最终审计因直接比较原始符号链接文本而失败；已定位 Python 原 data 解包过滤器移除一处 ./，第二次审计严格使用相同过滤结果比较并通过，原审计 exit=1、峰值和索引保留。此修正没有改动测量数据或源码。','',
      '## 审计与可追溯文件','',
      '独立最终审计 `final-audit-1` 实际 success/exited/0，峰值 {} 字节，swap/OOM=0；核对证据文件 {} 个。'.format(resource['memory.peak'],audit['evidence_files']),'',
      '- 结构化统计：`performance-summary-j16.json`；每轮详情：`audits/final-1/rounds.json`。',
      '- 逐点原始值与复算：`audits/final-1/statistics.json`。',
      '- 当前完整源码、Workspace 与预检重放报告：`audits/final-1/source.json`、`workspaces.json`、`preflight-replay.json`。',
      '- 证据索引：`audits/final-1/evidence-sha256.json`，SHA256 `'+audit['evidence_manifest_sha256']+'`。',
      '- 结果、资源、原始时钟：`results/final-audit-1.json`、`.resources.json`、`.time.txt`。',
      '- 所有数据位于 K3 的 `'+str(P)+'`；旧功能验收目录保持原样。未下载服务器大归档。','',
      '报告生成时间：'+summary['completed_utc']+'。']

    lines+=['','## 同16并发修正与原始CPU ticks复核','', '本报告全部Image为新的i5-*同16并发数据；旧-j8原生/-j16自动Image时长完全不混池，旧报告与全部证据原样保留。每组1次预热3次正式，正式组序轮换平衡。-j16是并行任务上限，不表示整个构建持续16核满载。make各组均原生运行，仅GCC树施加相应策略。', '', '原生每个GCC/cc1样本均为CPU0-7、Cpus_allowed_list=0-7、preference=none，实际迁移0；自动组每个新Image均观测到全部CPU0-15。保存的每进程PID/starttime/executable/CPU/ready摘要及CPU ticks前后值全部独立重算。', '', '| 正式Image组 | X100/A100整机平均活跃度 | 子进程CPU时间/墙时 |', '|---|---|---:|']
    image_cpu=[]
    for mode in modes[:3]:
        selected=[r for r in rows if r['kind']=='image' and r['measured'] and r['mode']==mode]
        busy={name:statistics.mean(r['metrics']['cluster_system_utilization'][name]['mean_system_busy_percent'] for r in selected) for name in ('x100','a100')}
        equivalent=statistics.mean(r['child_cpu_equivalent_cores'] for r in selected)
        observed=sorted({int(k) for r in selected for k in r['metrics']['cpu_observations']})
        image_cpu.append(dict(mode=mode,cluster_system_mean_busy_percent=busy,mean_child_cpu_equivalent_cores=equivalent,cpus_observed=observed,raw_cpu_ticks_recomputed=True))
        lines.append('| {} | {:.2f}% / {:.2f}% | {:.3f} |'.format(labels[mode],busy['x100'],busy['a100'],equivalent))
    lines+=['', '整机CPU活跃度包括操作系统等其他活动；子进程CPU时间包含make/编译/汇编/链接，除以编译窗口墙时表示平均消耗的CPU数量。离散CPU观测数不是CPU时间占比，不能据此宣称持续16核满载。', '', '首次同16并发补测prelaunch1因旧计划测试import旧controller而真实exit1，0 Image启动，原代码/日志/资源/索引全部保留；新attempt2明确版本只修复当前计划检查，其余13维护边界不变，共14项0跳过。', '', '图表：![同16并发性能对照](同16并发性能对照.png)']
    summary['image_cpu']=image_cpu;summary['old_j8_image_primary_comparison_superseded']=True;summary['old_image_times_not_pooled']=True
    write(out,json.dumps(summary,ensure_ascii=False,indent=2)+'\n')

    write(report,'\n'.join(lines)+'\n')
    output=dict(report_sha256=sha(report),report_bytes=report.stat().st_size,summary_sha256=sha(out),summary_bytes=out.stat().st_size,image_statistics=images,unit_statistics=units)
    write(P/'report-publication.json',json.dumps(output,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(output,ensure_ascii=False))

if __name__=='__main__':
    main()
    publication=load(P/'report-publication.json')
    write(P/'results/report-1.json',json.dumps(dict(passed=True,rc=0,**publication),ensure_ascii=False,indent=2)+'\n')
