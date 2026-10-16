# 栈对象、动态帧与未知尺寸范围

本分析回答两个独立问题：栈上是否还有需要原硬件宽度解释的向量数据，以及当前 SP 或其准备值是否依赖硬件 VLEN。没有向量访存的函数也可能分配动态帧；编译器已经给出完整栈对象 metadata 的函数仍需进行 SP 分析。

输入是单函数 CFG、目标栈语义、RVV 配置结果、metadata、最小 VLEN 与尺寸策略。输出包括逐指令 `live_before`、对象身份、访问模式、保守范围、分配／恢复来源、证明节点与缺口。全程序阶段随后执行[调用继承](call-boundaries.md)。

## 先决定哪些访问必须分析

选择器先构造函数内所有 VLEN 敏感向量访存的集合 `U`。整寄存器 load/store 始终进入集合；其他访存根据该点可能的 RVV 配置及 `min_vlen_bits` 判定。固定 AVL 只有在目标支持及容量条件得到证明时，才可能排除硬件宽度依赖。配置未知不能被当成固定宽度。

令 `M` 为 `U` 中有 `.chimera.stackobj_map` 记录的访问。metadata 选择按**整个函数**进行：

| 条件 | 使用的事实 |
|---|---|
| 没有 section | 对全部 `U` 执行二进制恢复 |
| 有 section，且 `U − M` 为空 | 使用编译器对象 ID |
| 有 section，但仍有未覆盖访问 | 整个函数回退到二进制恢复，分析全部 `U` |

部分 metadata 不会与二进制对象 ID 混入同一次 use/def。空 section、其他函数的记录或仅部分编译单元插桩，都不能授权忽略本函数的未覆盖访问。报告中的 `metadata_mode` 表示实际采用了 metadata；`has_metadata_section` 只描述存在性，二者不同。格式损坏的 metadata 由解析器拒绝，而不是作为空的可信信息使用。

## 恢复对象与求解生命期

二进制模式在指令执行前传播标量表达式。入口 SP、常量、寄存器输入和已支持算术组成规范化表达式；相同栈地址表达式复用同一个对象身份。访问地址被分为已恢复栈地址、已证明非栈地址和未解析地址。非栈访问不进入栈对象活跃性；未解析访问触发保守范围。

对已识别对象，向量 load 形成 `USE`，向量 store 形成 `DEF`。后向工作队列保留完整 CFG 的循环边，迭代至 `IN = USE ∪ (OUT − DEF)` 固定点。例如：

```asm
vs1r.v v8,(sp)      # 定义栈对象；旧对象内容在此可被替换
jal    ra,worker   # 后续 reload 使栈对象在调用前活跃
vl1re8.v v8,(sp)   # 使用对象
```

这里的对象活跃性判断“存储后的数据是否还会读取”。它不与[标量宽度私有槽的字节覆盖规则](scalar-width.md)混为一谈；后者还需要识别部分写、mask 和实际宽度内容。

无法恢复地址时，普通保守范围取包含访问的最内层自然循环；没有这样的循环则取函数范围，并排除该实现识别的函数出口。不可归约循环单独降级：循环内写入的标量表达式变为未知；其中的向量 store 建立不可归约对象，并在函数出口设置 use，使生命期不能因恢复失败而消失。保守范围属于分析结果，应在诊断中保留。

## 表达式、循环与来源证明

表达式求解与对象活跃性方向不同。表达式前向传播时，仅在这一阶段跳过自然循环回边；循环头把循环中会被写入的寄存器替换成稳定的 `LoopInput`，循环出口再规范化相关表达式。这样不会无限展开每轮迭代的算术。对象后向活跃性仍使用完整 CFG。

动态栈尺寸另有寄存器依赖状态，区分独立、已知 VLEN 和未知，并保存已知 VLEN 条件选择的来源。已知 VLEN 分支选择出的两个常量仍可能是 VLEN 相关尺寸；可靠汇合点可以结束结构性控制区域，但被选择值的来源仍随值保留。汇合后的无关赋值不会永久继承旧条件。

对尚未证明的 SP 调整，`OriginProver` 按需沿寄存器定义、内存写及函数摘要追溯。完整证明必须覆盖所有到达路径：知道 load 的地址在栈上，并不能证明该地址的内容独立；所有相关写入、字节覆盖、别名与可能写内存的调用都需有证据。摘要以形参和内存输入表达依赖，在调用点实例化。返回值依赖与每次内存写依赖分别保存，不能互相覆盖。递归摘要在有界求解后仍依赖自身未知答案时，结论保持未知。

证明返回独立、VLEN 相关或未证明的结果，并保留结构化原因与缺口。函数名、一个成功路径、部分覆盖和预算耗尽后的中间结果都不能成为独立性证明。当前来源证明版本为 `origins-v16`。

## 动态帧与准备阶段

帧分析前向传播每条指令后的动态帧状态，在汇合处保留可能活跃的路径。写 SP 时，若表达式证明恢复到可靠的入口 SP 基准及固定偏移，状态在该指令执行**后**解除；否则检查调整量的依赖与来源证明，未证明的调整默认激活动态帧。

setup 分析从敏感 SP 调整沿 CFG 向后追踪尚未证明独立的输入寄存器，标记调整前的准备／传递区间。直接读取 `vlenb` 但之后从不参与调整，不会凭读取本身制造动态帧；它是否构成标量宽度缓存由另一维度判断。

```asm
mv   s0,sp
csrr t0,vlenb
slli t0,t0,2       # setup：用于将来的栈调整
sub  sp,sp,t0      # 执行前 setup 活跃；执行后帧活跃
jal  ra,worker
mv   sp,s0         # 执行前帧仍活跃
nop                # 恢复后，若其他维度为空才可安全
```

已知独立的后续调整或被条件策略排除的 UNKNOWN 调整，不会清除此前已经激活的帧。解除仍要求可靠的恢复证据。

## UNKNOWN 的两种报告范围

默认 `unknown_stack_size_policy="conservative"` 把未证明独立的标量尺寸视为可能依赖 VLEN。应用集成者可以明确选择以下条件范围：

```toml
[[profile.workflow.steps]]
step = "safety"
parameters = { min_vlen_bits = 256, compiler_metadata = [], unknown_stack_size_policy = "assume-scalar-independent" }
```

该选择仅排除已经完成寄存器依赖固定点、又经过表达式及来源证明检查后仍未知的标量分配尺寸。调用者输入、内存加载、外部调用返回值以及来源证明预算缺口都可能落入这一假设范围。**排除是选择了假设，不是补出了证明。**

它不排除已知 VLEN、证明链中保留的 VLEN、已知 VLEN 分支选择值、向量栈对象、保守标记、不可归约退化或实际标量宽度缓存。寄存器依赖求解尚未达到固定点时，也不能应用该排除。

报告将策略、假设文本和 `conditional=true` 一并保存，即使 `scope_exclusions` 为空也如此；每项排除与仍活跃的 `frame_origins` 分开记录。check 与 prepare 必须使用相同策略，缓存重放会校验策略；不同策略的检查凭证不能互相授权。

## 预算与失败边界

| 边界 | 当前处理及结果 |
|---|---|
| 寄存器依赖更新预算 | 每函数 `4 × 指令数 + 256` 次更新；耗尽后丢弃部分寄存器与选择值状态，认证查询返回 UNKNOWN，保留 `register-dependency-budget-exhausted`，条件策略也不解除相关帧 |
| 结构性控制依赖 | 使用含正常返回和保守发散出口的逆图寻找可靠后支配边界；没有边界或边预算耗尽时，沿可达后继保守传播已知 VLEN 控制，记录 `known_control_fallback` |
| 来源证明 | 每次检查默认最多 `100000` 个证明节点及 `256` 次摘要请求；耗尽产生 `analysis-budget-exhausted`，不是独立性证明 |
| 摘要寄存器变化 | 每地址每寄存器超过更新上限后拓宽为未知；当前上限为 `6` |
| 标量宽度前向数据流 | 独立预算，耗尽时对整个函数保留宽度标记，见[标量宽度](scalar-width.md) |

`known_control_fallback`、寄存器固定点耗尽和全程序来源证明耗尽是三个不同事实。控制区域退化本身不证明某一尺寸来源于 VLEN；来源证明预算缺口也不能被描述成“已经证实尺寸独立”。报告必须保留条件与缺口，而不只展示 finding 数量。

## 源码与回归

主路径是[访问筛选与对象事实](../../../../preprocessing/offline/analysis/safety/stack_liveness/accesses.py)、[表达式求解](../../../../preprocessing/offline/analysis/safety/stack_liveness/solver.py)、[循环识别](../../../../preprocessing/offline/analysis/safety/stack_liveness/loops.py)、[依赖求解](../../../../preprocessing/offline/analysis/safety/stack_liveness/dependencies.py)、[动态帧](../../../../preprocessing/offline/analysis/safety/stack_liveness/frame_liveness.py)和[来源证明](../../../../preprocessing/offline/analysis/safety/stack_liveness/origins.py)。

关键回归包括[metadata 地址与覆盖](../../../../tests/test_stackobject_metadata_addresses.py)、[动态帧和条件范围](../../../../tests/test_vlen_stack_liveness.py)、[依赖预算](../../../../tests/test_vlen_dependency_budget.py)、[控制区域对抗用例](../../../../tests/test_vlen_control_region_adversarial.py)及[Profile 范围传递](../../../../tests/test_unknown_stack_scope_profile.py)。返回[安全点总览](README.md)。
