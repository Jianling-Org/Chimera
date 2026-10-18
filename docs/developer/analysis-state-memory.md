# 分析状态内存：紧凑逐地址状态

`check-elf` 与 `prepare` 的 safety 阶段共用向量配置、向量寄存器活性、栈活性和调用传播分析。紧凑逐地址表示减少长期保留状态的分配，同时保持全部函数、指令、诊断与检查语义。

## 1. 紧凑逐地址状态映射

新增 `core/algorithm/address_states.py`，用「地址域 + 共享默认值 + 例外字典」表示
逐地址状态：

* **地址域**是去重后的地址元组，保留首次出现顺序；成员查询对该元组排序副本做二分，
  不另建逐地址字典。元组本身已经严格递增时直接复用，不做二次拷贝，因此**同一函数的
  所有相关结果共享同一个地址域对象**。
* **共享默认值**：没有例外条目的地址一律解析到同一个对象（例如空集合）。
* **例外字典**只保存与默认值不同的条目，即真正需要长期保留的稀疏状态。

`AddressStateMap` 的可见行为与它所替代的稠密字典一致：`mapping[address]`、`get`、
`in`、`len`、迭代、`items` 与映射相等比较全部保留；**值为空的已知地址仍然属于映射**，
域外地址按普通的 `KeyError` / `get` 默认值规则处理；相等比较是映射语义而不是表示语义，
两个域顺序不同但键值相同的映射仍然相等。结果类型标注从具体 `dict` 放宽为只读
`Mapping`，测试与调用方传入的普通字典继续可用。

需要显式完整字典的既有接口（如 `StackLivenessResult.live_before`、
`flattened_live_before`）继续支持，但正常分析路径不会隐式展开。

## 2. 三个阶段的具体改动

| 位置 | 改动 |
| --- | --- |
| `arch/riscv/rvv/config.py` | `VectorConfigResult.before_by_address` 改用紧凑映射，默认值是与 `UNKNOWN_CONFIGS` 共享的同一集合；单函数分析内复用相同配置集合；去掉 `dict.get` 默认表达式每次构造 `_State` 与集合的开销。配置传播、常量合并、不可达指令与 VSET 规则不变。 |
| `core/algorithm/dataflow.py` | 通用后向求解器只保存非空状态，空状态共享同一不可变集合，收敛回空时删除条目；返回仍可查询全部地址的紧凑映射。转移顺序严格保持 `uses \| (after - def)`——既读又写同一事实的 keep-vl `vsetvli` 必须保持状态寄存器 live-in。 |
| `safety/stack_liveness/frame_liveness.py` | VLEN 栈帧标记与保守标记合并改成稀疏条目；「整个函数保守」与「仅可达地址保守」两种情况继续区分，VLEN 栈帧、恢复点与保守边界语义不变。 |
| `safety/stack_liveness/liveness.py` | 保守合并只处理非默认状态与需要标记的地址；栈对象与栈帧状态按稀疏条目合并；调用继承改为只读的「基础映射 + 继承标记」视图（`InheritedLivenessView`），不再为继承闭包中每条指令常驻一份新字典和新集合。标量表达式分析、调用闭包、seed hosts、residual 与不可归约循环判定完全未动。 |

向量寄存器活性（`arch/riscv/rvv/liveness.py`）与栈活性共用同一个求解器，因此两者同时
受益；`VectorFunctionLiveness.live_before` 与 `StackFunctionLiveness.live_before` 现在是
只读 `Mapping`。

## 3. 阶段监测

`core/monitor/memory.py` 提供 `PhaseMemoryMonitor`：

* 在向量配置、局部栈分析、调用传播的开始与结束记录 RSS、峰值 RSS、swap（MiB）；
* 每完成 100 个函数输出一次累计进度与**实际保留的状态条目数**；
* 单个函数耗时 ≥ 5 s 或完成前后 RSS 增长 ≥ 64 MiB 时，输出函数名、起始地址、指令数、
  保留条目数与前后内存；
* 阶段边界立即刷新；任何探测失败都只是不输出该行，绝不影响检查本身；不做对象图遍历
  之类的高开销追踪。

这些行沿用仓库既有的 `--debug` 监测通道，因此普通运行的输出完全不变。瞬时峰值仍由
外部采样与 `/usr/bin/time -v` 辅助判断。

## 4. 回归与基准

* `tests/test_compact_state_map.py`：映射行为本身——空状态、已知地址默认值、域外地址的
  `KeyError`/`get`、`len`/迭代/`items` 顺序、与普通字典双向相等、去重与保序、例外计数。
* `tests/test_analysis_state_regression.py`：
  * 用本模块内的稠密参考实现（改写前的写法）逐地址对照后向活性、VLEN 栈帧标记、保守
    标记合并、继承标记与向量配置收集；
  * 覆盖空状态、分支合并、自然循环、不可达指令、VLEN 动态栈帧、不可归约循环、元数据
    模式、递归调用、继承标记、保守作用域与 residual；
  * **固定版本差分**：同一批 fixture 分别由当前分析器与从 `93419dd7513befb00a1d8a3c2853c4001ffea9b0`
    取出的分析实现各自在独立进程中执行，逐地址配置集合、向量/栈活跃集合、warnings 及
    其 support 明细、继承闭包、findings、gate 名单、decision 与最终逐指令安全分类必须
    完全一致。比较版本使用固定 commit SHA。
* `tools/bench_analysis_memory.py`：内存基准，同样以 `93419dd` 为固定比较版本，把旧实现
  真实装载（`git show <sha>:<path>` 后强制注册）后在新进程里运行，因此测的是改写前的
  稠密求解器，而不是当前代码里的一个开关。

```text
python tools/bench_analysis_memory.py --instructions 150000 \
    --json build/bench/analysis-state-memory.json
```

基准分开测量程序模型、配置结果、局部结果累计与继承传播四个阶段，各自记录耗时、峰值
RSS、**实际占用的映射槽位**与**非空状态数**，并输出语义摘要用于比对。

## 5. 目标机验证

合成基准只衡量状态表示的分配与语义，不替代真实输入的峰值资源、数值结果或迁移验收。差分测试需要提供指定比较版本的源码；运行前核对该提交可读取，测试结果应列明实际执行的比较范围。

目标机验证应保存当前源码、ELF、Profile、工具版本、阶段日志、峰值 RSS、检查结果及后续 prepare/verify 和动态证据。大型正式准备使用常规诊断级别；需要 debug 追踪时单独记录额外开销。复验流程见[构建与测试](build-and-test.md)和[端到端应用集成](../deployment/end-to-end-rvv.md)。
