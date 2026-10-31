# K3 GCC 64任务并发矩阵

本目录补充2026年10月29日执行的64任务测试脚本，对应性能报告2.2节。被测Chimera提交为`578ab8321c0788ab8cba1ad24324f220e1e4a149`，内核为`6.18.3-chimera-d02cd7352`，范围为`assume-scalar-independent`。归档时未重新运行硬件测试。

## 测试范围

固定64条真实Kbuild编译命令，比较原生X100、prefer-x100、prefer-a100和静态分簇四种模式。并发为1/8/16/24，每点1预热、5正式，共96轮，其中80轮正式。单位任务原生与自动组使用相同任务并发上限。

| 并发 | 原生X100秒 | prefer-x100秒 | prefer-a100秒 | 静态分簇秒 |
|---|---:|---:|---:|---:|
| 1 | 223.215 | 225.746 | 476.434 | 223.289 |
| 8 | 36.565 | 44.308 | 53.172 | 52.112 |
| 16 | 37.001 | 29.548 | 37.043 | 35.118 |
| 24 | 36.674 | 28.624 | 31.817 | 39.572 |

表内为5次正式测量中位数。[统计文件](results/unit-statistics.json)包含各点原始5次耗时、范围、吞吐、速度比和提取来源SHA。它只选取原摘要的单位任务字段，不包含任何旧Image时间。

静态模式使用共享队列和固定簇worker；并发1仅使用X100，并发8/16/24分别为4+4、8+8、12+12个worker。它不是把64任务按核数预分成两个互不相通的队列。

## 执行快照

`harness/setup_performance.py`和`setup_performance_v2.py`保留源码隔离、配置、prepare/scripts、64条实际命令提取及原生产物参考建立过程。`performance_preflight.py`核对四组正确性、初始化与物理迁移。`prelaunch_attempt2.py`核对新轮次身份和容量。

`performance_round_v2.py`为单位任务worker，记录内部monotonic窗口、原生产物比对、0.5秒CPU/温度/频率/内存采样和30秒存储健康采样。准备、SHA核对和冷却在计时外，启动/bootstrap/迁移在计时内；外层time-v只作资源旁证。正式性能窗口不启用详细kprobe。

`performance_controller_v2.py`保留原控制器全部108轮计划，其中最后12轮是已弃作主比较的旧Image协议：原生-j8、自动-j16。**不要直接启动该控制器重跑单位矩阵。** [unit-plan.json](results/unit-plan.json)仅提取其96轮单位任务计划，不是新的执行控制器。当前完整Image主比较和CPU利用率仍使用[同16并发归档](../k3-20261030/README.md)，三组均为-j16。

`perf_common.py`依赖原验收目录的`runtime_smoke`、`migration_trace`、`runtime_acceptance_v5`和`kernel_event_policy`，这些原版本已归档在[验收脚本目录](../../gcc-validation/k3-20261029/harness/)。本目录保留原绝对路径；对应的ELF、Profile、注册表、Workspace、kernel-source、seed、config.common、tasks.json和环境仍是板端输入，不随仓库分发。`setup_performance.py`记录其生成过程，固定config及tasks SHA也由prelaunch核对。

## 存储与结果边界

性能策略允许实际BKOPS0/1/2，并仅将priority 3、同一`c0e00000.ufshc`控制器、完整`ufshcd_bkops_exception_event_handler`的status1/2维护消息分类保留。实际status3或未知、critical health非零、I/O及其他未知告警仍失败。原始字节、序号、时间和SHA均由采集器保存；离散健康采样不能推断维护状态持续时长或因果性能损失。

原失败数据与attempt2分开。归档没有把旧失败改为成功，也没有把旧Image、旧单位轮次或后续同16并发Image时间混池。

## 离线回归

```sh
python -B -m unittest discover -s experiments/gcc-performance/k3-20261029/harness -p 'test_perf_policy_v2.py' -v
```

离线环境执行12项纯边界测试；另外2项原用例需要板端证据及完整路径，会明确跳过。新硬件运行需要新的实验根、轮次和冻结计划，不能覆盖已有结果。

各快照及提取结果的SHA见[provenance.json](provenance.json)。本目录只公开执行快照和小型摘要，不包含完整板端原始日志。许可证见[LICENSE.md](LICENSE.md)。
