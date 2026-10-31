# 按进程选择迁移策略

bootstrap 启动时可以明确选择一种策略：

```sh
chimera-user run --registry /absolute/registry.tsv --bootstrap /absolute/libchimera-bootstrap.so \
  --preference prefer-x100 /absolute/program argument
chimera-user run --registry /absolute/registry.tsv --bootstrap /absolute/libchimera-bootstrap.so \
  --preference prefer-a100 /absolute/program argument
```

`--preference` 隐含 `--automigrate`，必须同时提供 registry 和 bootstrap。
普通八核对照仍直接执行普通程序，不传这些参数、不加载 bootstrap。
仅传旧参数 `--automigrate` 时选择 `prefer-a100`，不再受板级启动参数影响。

* `prefer-x100`：每一层先分配 X100 槽位，再分配 A100 槽位，适用于当前 GCC 标量实验。
* `prefer-a100`：每一层先分配 A100 槽位，再分配 X100 槽位，保留原向量负载策略。

两种策略可以同时运行，逻辑槽位和待提交转移数量分别记账；实际 CPU、CPU 预留、工作队列仍共享。
这不是两套独占 CPU 分区，也不是按 2.67 核心速度加权的调度器。

内核接口分别为 `/proc/prefer_x100`、`/proc/prefer_a100`，写入格式相同：

* `inherit:TID`：选择策略并要求每次 exec 后重新 ready。
* `TID`：准备完成后的显式启用，主要用于现有直接控制接口。
* `ready:TID`：只发布本线程组的准备状态，保留已经继承的策略；可从任一接口写入。
* `-TID`：关闭并清理提案、预留和逻辑分配。

策略由 fork/clone 子任务继承，exec 保留策略，但清除旧映像 ready 状态、处理器和映射。
bootstrap 只在新 ELF 的身份和运行时初始化验证成功后发布 ready。
`/proc/PID/status` 的 `Hmp_preference` 显示 `none`、`prefer-x100` 或 `prefer-a100`。
旧 `Prefer_a100` 字段仍表示“已启用自动策略”，用于旧 bootstrap 兼容，并非所选方向。
共享确认接口 `/proc/prefer_a100_ack` 保持不变。

启用期间不能直接改变策略，返回 `EBUSY`；须先关闭、清理后重新启用。
旧只读启动参数 `hmp.prefer_regular_first` 被任务级选择替代。
旧内核没有 `/proc/prefer_x100` 时明确启动失败，不静默改用 A100。

使用前须安装提供这两个接口的内核；`6.18.3-chimera-bootstrap-exec-signal-depth-task-preference-v1` 已提供支持。
当前已验证标量 GCC 的策略继承、两种负载并存、真实双向迁移及退出清理，并完成长期稳定性检查。
该支持范围不包含自动向量化 GCC 或 RVV/llama 的最终安全验收。
旧 regular-first-v1 的性能测量属于全局策略版本，不能直接用作本接口版本的性能结论。
