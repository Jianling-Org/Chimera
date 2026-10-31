# K3 GCC 子进程迁移验收与准备时间

本记录对应2026年10月29日完成的GCC验收。被测Chimera提交为`578ab8321c0788ab8cba1ad24324f220e1e4a149`，内核为`6.18.3-chimera-d02cd7352`，静态安全范围为`assume-scalar-independent`。本目录补充性能报告4.3节和第5章的原执行脚本及结果索引；归档时未重新运行板端测试。

## 验收结果

| 项目 | 编译轮数 | 编译链数 | 256→1024提交 | 1024→256提交 | 同一TID往返 |
|---|---:|---:|---:|---:|---:|
| matrix-3 | 15 | 210 | 92 | 104 | 82 |
| stability-2 | 383 | 4680 | 2270 | 1993 | 1652 |

matrix-3和stability-2均实际`success/exited/0`。stability-2有效混合负载7216.573023秒，峰值内存2311704576字节，swap峰值和OOM kill均为0。独立终审核对11117个证据文件、两套Workspace共78行receipt，以及全部398轮、4890条编译链记录。

stability-1在严格告警策略下因UFS status1消息停止，未完成两小时；[保留记录](results/stability-1-record.json)未改为成功。后续stability-2仅将priority 3、控制器`c0e00000.ufshc`、`ufshcd_bkops_exception_event_handler`完整status1维护消息及对应设备上下文单列保留，共4次。其他告警、实际BKOPS2/3、critical health非零、I/O错误、证据丢失和迁移超时仍失败。这与后续性能实验允许实际BKOPS0/1/2的规则不同。

## 脚本

- `harness/runtime_smoke.py`：实际xgcc→cc1链、确定性C输入和数值参考。
- `harness/runtime_acceptance_v3.py`：matrix-3，包括1/8/16/24并发、标量/RVV目标与重复运行。
- `harness/runtime_acceptance_v4.py`：保留stability-1的严格告警版本。
- `harness/runtime_acceptance_v5.py`、`start_runtime_stability_2.py`：stability-2执行和前置核对。
- `harness/migration_trace.py`、`readiness_probe.py`：按同TID/generation匹配成功ACK、物理CPU提交及每exec初始化证据。
- `harness/kernel_event_policy.py`、`final_independent_audit.py`：内核原始记录分类与独立重放。
- `harness/setup_remote.py`、`worker.py`、`controller.py`：输入准备、阶段命令和有界systemd调度。
- `harness/record_cgroup.py`、`phase_outcome.py`、`resource_policy.py`：真实退出、资源记录和准备阶段预算。

这些文件为当时执行版本的字节快照，本地模块依赖已随附。原预检使用pyelftools 0.33和pytest 9.1.1，版本见[requirements.txt](requirements.txt)；生产CLI由所标识的Chimera源码提供。运行时还需对应内核接口、tracefs、固定ELF/Profile、注册表、Workspace及原证据目录。

## 构建和准备时间

| 阶段 | 成功尝试 | 秒 |
|---|---:|---:|
| `make -j2 all-gcc` | 1 | 5133.349442 |
| xgcc双向Workspace准备 | 1 | 1190.410337 |
| cc1双向Workspace准备 | 2 | 27556.452373 |

[阶段记录](results/preparation-record.json)从本地checkpoint选取对应字段，并记录来源SHA；它是摘要，不是原始逐阶段日志。三项是各自一次成功执行，不能作为多次正式性能测量的中位数。准备阶段采用独立资源策略，cc1准备的swap峰值为12063731712字节，不能套用正式Image测试的零swap条件。

`resource_policy.py`保留当时的临时swap管理，`controller.py`保留所有阶段及失败重试边界。本目录不是通用安装器；不要在已完成实验根直接执行。新的硬件复测须另建实验目录、修改并冻结路径与轮次身份，先完成输入和容量核对，准备时间也须区分全新输出与复用命中。

## 离线检查

在仓库根运行，只执行解析、退出分类和预算边界回归，不启动硬件负载或修改swap：

```sh
python -B -m unittest discover -s experiments/gcc-validation/k3-20261029/harness -p 'test_*.py' -v
```

[终审摘要](results/final-audit-result.json)、[终审退出资源](results/final-audit-resources.json)和[完成记录](results/completion.json)保留原字节。[provenance.json](provenance.json)记录每个快照及结果文件的SHA。仓库不包含全部板端原始证据；离线回归不能代替重新核对这些原始证据或实际迁移。

性能报告的对应修改和本次未整理项目见[反馈说明](../../../docs/validation/performance-report-feedback.zh-CN.md)。许可证见[LICENSE.md](LICENSE.md)。
