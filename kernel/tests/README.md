# 内核测试与配对验收

有序补丁重放后，内核源码包含 `tools/testing/selftests/riscv/prefer_a100/`：`scalar.c`、`run.py`、`sleep_wakeup_smoke.py` 和自动分布/trace诊断脚本。这些脚本可能改写调度控制接口，只在隔离测试板执行，并先阅读脚本、确认没有其他任务。

`run.py` 是原生标量调度测试，不能证明跨VLEN转换正确。自动迁移功能的最终门槛见 [自动迁移验证](../../docs/validation/automigration.md)。必须对同一用户态/内核配对验证原始成功ACK、内核实际CPU迁移、runtime状态链、数值结果、账本清理及全程告警，不能只看proposal计数或脚本退出码。

内核安装/启动前还需审查panic、锁顺序、task退出、reservation泄漏、signal frame及translated重入；构建脚本本身不执行安装或重启。
