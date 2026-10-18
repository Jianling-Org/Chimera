# RISC-V SBT 架构与 RVV 翻译流程

本文档说明当前翻译器的模块边界、程序级 CFG（控制流图）与 vtype/AVL（活动向量长度）分析，以及控制流重写规则。代码是实现事实的最终来源；本文档用于解释接口、数据流和边界，不替代 dispatcher、handler、测试或目标机验证。

## 统一翻译流程

```text
AsmParser
  → RVProgram / RVFunction / RVInstruction
  → TranslationPipeline.prepare()
      → analyze_structure() → ProgramStructure（CFG、调用图、指纹）
      → VectorConfigAnalyzer(program, structure) → RVV ProgramAnalysis
      → 结构校验与后端纯 preflight
      → PreparedTranslation
  → ProgramEmitter.emit(prepared, EmissionOptions)
      → ControlFlowEmitter
      → VTypeDispatchEmitter（路由与候选分发）
      → backend.plan() / backend.lower()
      → VectorBlockEmitter
  → 目标汇编
```

程序级入口会自动执行一次 CFG/vtype 分析、结构校验和后端预检。JAL
范围探测的每一轮只新建 `EmissionOptions` 与 `EmissionSession`，复用同一份
不可变、只能由 `prepare()` 构造的 `PreparedTranslation`。诊断和标签计数
只存在于当前 `EmissionSession`，不会写回准备结果。严格后端的 preflight
planner 在构造 `TranslationPipeline` 时固定，`prepare()` 不接受临时注入的
预检/旧分析对象。输入文本中的 `# source:` 注释只作为普通汇编注释处理，
不再是程序级翻译的语义来源。

## 模块职责

| 模块 | 职责 | 对外依赖边界 |
|---|---|---|
| `frontend/` | 程序模型、解析、CFG/调用图、结构分析 | 不依赖 RVV |
| `codegen/`、`registers.py` | 控制流重写、JAL 对象检查、寄存器事实 | 不依赖 RVV 状态 |
| `extensions/rvv/analysis/`、`instruction.py` | 配置事实、状态机、数据流分析 | 不导入运行时布局、翻译执行或后端 |
| `extensions/rvv/translation/` | prepare、规格装配、指令分发、结果保护 | 使用后端接口；contracts 不导入 pipeline |
| `extensions/rvv/runtime/` | 状态布局、方向几何、TLS 与输出契约 | 不处理指令族 |
| `extensions/rvv/backends/` | scalar、rvv256、rvv1024_transition | 后端互不依赖；validation/operands 不导入 handlers |

完整 pipeline 和 ProgramEmitter 是当前 RVV 场景的组合者。扩展点首先体现在
共用程序处理能力可以独立使用，尚未建立多扩展自动注册和组合框架。

dispatcher 的正式 handler 合同统一为
`handler(HandlerContext, LoweringPlan) -> LoweringResult`。复杂指令模块中的
私有 `_build_*_lines(context)` 仅是后端内部成功路径 assembly builder；
registry.lower 将 plan.normalized_operands 绑定到独立指令副本，保留 plan.instruction 的源身份。私有 builder 只消费绑定后的上下文；它们由结构化 lowerer 调用，不能被 emitter 直接当作 handler，
也不存在旧四参数兼容入口。寄存器破坏、语义输入输出、状态读写和
诊断都来自 `InstructionSpec` / `LoweringResult`，不再反解析汇编字符串。
`LoweringResult` 也不实现列表/序列接口；调用方必须显式读取
`assembly_lines`，防止忽略其余结构化状态。
需要在状态收尾之后才提交的客体语义结果由 `AssemblyFragments` 的
`post_state_lines` 明确表达，不再用特殊汇编注释标记和字符串扫描调整次序。
三种 dispatcher 也不再保留 `dispatch()` 便捷门面；唯一调用链是
`make_context()`、`plan()`、`lower()`，由 `VTypeDispatchEmitter` 统一编排。


`HandlerContext` 仅持有单条指令、配置状态、布局、标签分配函数、临时寄存器分配器和绑定规格。没有 dispatcher、重复 allocator、整程序 analysis 或 emission_session 字段。EmissionSession 本身仍由 pipeline 每轮创建，类型位于 contracts；分发器显式消费 profile 与 session，不回依赖 pipeline。

过渡后端的 guard、vcsr/vstart 收尾由 lowerer 持有，并在寄存器破坏捕获范围内执行。state_view 直接提供紧凑布局函数，不再通过 dispatcher 上的静态方法门面获取。validation 与 handlers 共同消费 operands 中的纯形状/CSR 规则。

宽路径由 planning.py 负责寄存器组和 EMUL 规划，wide.py 生成汇编；lowering.py 保持候选选择顺序并传递已选规格，wide 不回查 registry。StateTracker 的源宽度由调用方显式提供，配置模型不从运行时 ABI 取得默认值。

### fallback 文案的所有权

`fallback_policy=ebreak` 的后端必须实现
`dispatcher.fallback_result(insn, reason) -> LoweringResult`，由后端品牌化
生产注释文本（RVV256 输出 `RVV256 fallback`，RVV1024 过渡路径输出
`RVV1024 fallback`，均被 CLI 测试消费）。
`VTypeDispatchEmitter` 在 ebreak 策略下优先使用后端结果，仅当返回
`None` 时退回 core 通用模板；`raise`/`reject` 后端不会被调用，但三个
dispatcher 都显式实现该方法以暴露误配置，而不是静默退回通用模板。
这样无论失败发生在 registry 查找、validator 还是 builder 阶段，同一后端
只有一种诊断文案来源。

## 内部 CFG 与 vtype/AVL 分析

### 实现位置

- `src/riscv/frontend/parser.py`：解析地址、label、operand、原始字节、`target_address` 和 `target_symbol`；
- `src/riscv/frontend/cfg.py`：构造基本块、前驱/后继、入口和未知出口；
- `src/riscv/extensions/rvv/analysis/dataflow.py`：工作表前向数据流、vtype 候选合并和标量常量传播；结果保存在 RVV `FunctionAnalysis.instructions` 中，按源指令地址查询；
- `src/riscv/frontend/call_graph.py`、`text_index.py`：函数边界与文本索引辅助；
- `src/riscv/extensions/rvv/translation/pipeline.py`：程序级入口 `analyze_program()`，先调用共用 `analyze_structure()`，再执行 RVV 分析并返回组合结果；
- `src/riscv/extensions/rvv/analysis/model.py`、`src/riscv/extensions/rvv/analysis/model.py`、`src/riscv/frontend/model.py`：只保存结构化分析结果，不生成后端汇编。

### CFG 能力和保守边界

当前 `CFGBuilder` 支持并保守处理：

- 顺序执行和函数内直接目标；
- 条件分支的目标边和 fall-through（顺序落下）边；
- `j`、`tail`、`jal x0` 等无条件控制转移；
- `jal`/`call` 的调用者 fall-through；
- 循环、多前驱汇合和基本块前驱/后继关系；
- 同一函数范围内没有前驱的块作为次级入口候选，而不是直接伪造为死代码；
- `jr`、`jalr x0` 和无法解析的间接目标作为 `unknown_exit`；`jalr` 调用形式保留 fall-through，但仍使后续 vtype 保守未知；
- `target_address` 优先于重新解析 operand，避免丢失 objdump 已解析的目标地址。

未知间接跳转不会被猜成某个确定目标。这样可能减少静态确定范围，但不会把错误的 vtype 传播到不可证明的路径。

### vtype 候选模型

`VTypeSpec` 只表示字段完整且确定的 `SEW`、`LMUL`、`VTA`、`VMA`。数据流阶段使用 `VTypeCandidate`，它可以显式保存：

- `sew`、`lmul`、`vta`、`vma`；
- `AVLInfo`：`x0`、静态常量或未知，并保留来源寄存器；
- `source_instruction`：产生该配置的 `vset*` 地址；
- `unknown_reason`：动态 `vsetvl`、入口缺少状态、调用可能修改 vtype、缺字段等原因。

缺失 `VTA`/`VMA` 时不会默认填充 `ta`/`ma`。只有 `known_vtype` 的候选才能转换成旧 emitter 使用的 `VTypeSpec`；未知候选继续保留在 `InstructionAnalysis.possible_vtypes` 中，并令 `vtype_unknown=True`。

### 数据流转移和合并

`VectorConfigAnalyzer` 使用前向 worklist（工作表）算法：

1. 主入口以 unknown vtype 开始；次级入口也以独立的 unknown 原因开始，不能继承主入口外部状态；
2. `vsetivli`、`vsetvli` 解码立即数或经过常量传播的 AVL，并解析 SEW/LMUL/VTA/VMA；
3. `vsetvl` 的 vtype 来自运行时寄存器，当前只保留 AVL 信息并将 vtype 标记为未知；
4. 条件分支沿所有可解析后继传播；循环在状态达到不动点后结束；
5. 多前驱汇合采用 may-set 合并 vtype 候选，只有所有前驱都给出相同值的标量寄存器常量才保留；
6. `li`、`mv`、`addi`/`addiw`、`add`、`sub`、`lui` 支持有限标量常量传播；调用和 `jalr` 会清除可能被调用者破坏的 caller-saved（调用者保存）常量；
7. 直接调用后不沿用调用前的 vtype，因为被调函数可能执行 `vset*`；
8. 无法到达或未识别入口的指令保留独立的 unknown provenance（来源），不能伪装成静态确定。

### 分析结果的挂接与消费

对每条指令，`InstructionAnalysis` 保存：

- `possible_vtypes`：所有可能候选（`VTypeCandidate`，允许字段未知）；
- `definite_vtype`：只有单一完整候选时才设置；
- `vtype_unknown`：是否存在不完整候选；
- `avl_information`：候选 AVL 集合；
- `provenance`：分析来源标识（当前内部 CFG 为 `internal-cfg`）。

`analyze_structure()` 生成 `ProgramStructure`，按函数起始地址保存结构信息、
调用图、输入指纹及结构统计。RVV `ProgramAnalysis.structure` 引用该对象，
`functions` 按函数起始地址保存 RVV 结果；其中 `instructions` 按源指令地址
保存 `InstructionAnalysis`。基础程序和指令不承载扩展分析结果。
`VectorConfigAnalyzer` 消费结构，不重建 CFG，也不修改入口标记。后端消费两个安全接口：

- `known_specs()`：只返回 SEW/LMUL/VTA/VMA 四字段都被静态证明的
  `VTypeSpec`，“未知候选不能转换”这一边界由模型层保证；
- `has_unknown_candidate()`：判断是否仍存在不能静态解释的 vtype 路径。

因此后端可以在单候选直接降低、多候选运行时按模拟 `CSR.vtype` 分发、
或 fail-fast 之间选择，而不会拿到伪造的完整 vtype。

历史输入中的 `# source:` 注释不再被解析为语义来源，只作为普通汇编注释
保留；不存在注释写回器或 `source_vtypes` 兼容字段（有静态测试锁定该
属性不会重新出现）。

### 当前分析边界

- 间接跳转目标无法静态解析时，只能保守标记未知出口；
- 当前没有跨函数 vtype 摘要，调用返回点会丢弃静态 vtype；
- 标量常量传播不是完整的 RV64 值集分析，不应替代真实寄存器值；
- `vsetvl` 的运行时 vtype 不能靠静态 CFG 恢复；
- CFG 分析正确并不等于后端支持对应 opcode/form，也不等于目标机语义正确。

后续扩展应优先增加分析结果的来源信息、调用摘要和未知原因测试，而不是把未知状态强行压成某个默认 vtype。

## 后端命名空间与能力来源

`src/riscv/extensions/rvv/backends/` 是唯一后端命名空间，旧 `isa_rvv`、`isa_rvv256`、
`isa_rvv1024` 导入路径已直接删除，不提供转发壳或 `sys.modules` 别名。
每个后端只通过 `HandlerRegistry` 查询能力；opcode、form、SEW/LMUL、mask、
tail、`vstart`、旧 `vd` 和 lowerer 绑定由 `InstructionSpec` 统一描述。支持
文档由 registry 生成，避免 dispatcher、文档和预检维护多份白名单。
`StateTracker` 的实际定义也只位于 `src/riscv/extensions/rvv/analysis/config.py`，不再通过
`core/middle_end` 转发；状态默认宽度和槽位偏移统一来自 `src/riscv/extensions/rvv/runtime/layout.py`。

### 翻译方向几何的唯一权威

`src/riscv/extensions/rvv/runtime/geometry.py` 的 `TranslationGeometry` 是源/目标 VLENB、方向比值
和全部派生量（块元素数、块字节数、源 VLMAX、整寄存器搬运宽度）的单一权威：

- 已登记方向只有 `128→32`（RVV1024→RVV256）和 `32→128`（RVV256→RVV1024
  过渡）；`geometry_for_direction()` 拒绝未登记组合，因此非法 `--vlenb`
  在 profile 构造期即 fail-fast，不会静默生成与状态槽布局矛盾的代码；
- RVV 1.0 的 LMUL 合法集与 token 表定义在 `src/riscv/extensions/rvv/analysis/model.py`
  （`LEGAL_LMULS`/`LMUL_TOKENS`），core 与后端只引用；
- 运行时 vtype→VLMAX 解码（含 vill、`vtype[62:8]` 保留位、保留
  `vlmul=100` 检查）统一由 `src/riscv/extensions/rvv/translation/vtype_decode.py` 发射，两个后端
  不再各自维护副本。共享后 RVV256 的 `vsetvl` 与过渡路径行为一致：
  保留位非零的 vtype 走 vill 收尾（`vill=1, vl=0`），不会截取低 8 位
  按错误形状继续执行；
- 状态基址标记 `CHIMERA_STATE_BASE` 只在 `src/riscv/extensions/rvv/runtime/access.py`
  定义一次。

`tools/check_backend_quality.py` 会拒绝在后端代码中重新内联这些字面量，
并禁止 bare/broad `except Exception` 与函数内延迟 `import riscv.extensions.rvv.backends.*`
（出现模块环时应抽出中立模块，如两个后端的 `lowering_metadata.py` 或
core 的 `spec_seeding.py`）。
`tests/test_geometry.py` 锁定方向白名单与派生量，
`tests/test_vtype_decode.py` 锁定“两个后端的解码序列仅源 VLENB 一行不同”。

## 程序级控制流重写

### 基本术语

- `rd`：RISC-V 指令格式中的目标寄存器字段；在 `jal rd, target` 中保存返回地址；
- `ra`：return address（返回地址），对应硬件寄存器 `x1`；
- `x0`：恒为零的寄存器，写入结果会被丢弃；
- 自定义 link register：`rd` 既不是 `ra` 也不是 `x0`，例如 `jal t0, target`。

### 控制流分类

| 类型 | 典型形式 | 是否保存返回地址 | 翻译含义 |
|---|---|---:|---|
| 调用型 | `jal ra,target`、`call target` | 是 | 调用已翻译函数或外部 `@plt` 目标 |
| 尾跳型 | `j target`、`jal x0,target`、`tail target` | 否 | 函数内 `j` 默认保持短跳，确认越界后经内部长跳跳板；跨函数或外部目标使用 `tail` |
| 自定义链接寄存器 | `jal t0,target` | 是 | 保留 `rd` 语义，只改写目标；对 `@plt` 当前降级为 `ebreak` |
| 条件分支 | `beq/bne/blt/... target` | 否 | 函数内目标改写为地址标签 |
| 间接跳转/调用 | `jr`、`jalr` | 取决于 `rd` | 通过地址映射查询翻译目标后再跳转 |
| 返回 | `ret` | 读取已有 `ra` | 查询映射后恢复正确返回目标 |

`ControlFlowEmitter` 是控制流职责边界，由 `ProgramEmitter` 组合使用，负责：

- `branch_j_target_<addr>` 地址标签；
- 函数内和跨函数直接跳转；
- `ret`/`jr`/`jalr` 地址映射；
- `auipc` 原始基址恢复；
- PIC（位置无关代码）共享对象约束。

### 目标标签和改写规则

函数内部的条件分支使用：

```asm
branch_j_target_<addr>:
    ...
    bnez    a4, branch_j_target_<addr>
```

函数内部的无条件 `j` 仍以 `branch_j_target_<addr>` 作为唯一迁移入口，
正常翻译轮默认直接发射短 `j`。当翻译器内部的对象级范围检查确认该 site
超出 JAL/RVC jump 范围后，后续轮次才在目标标签前放置跳板：正常顺序流
用相邻短跳越过跳板；真正的本地长跳通过 `auipc`/`jalr x0` 到达跳板，
由跳板恢复保存的 `t0` 和 `sp` 后再进入原有 `branch_j_target`。这样不依赖
原始函数边界推断翻译后代码距离，也不增加新的 offset map 或迁移安全点。

跨函数直接调用使用 `<original_func_name>_translated`：

```asm
call     ggml_cpu_init_translated
```

目标类别和基本规则如下：

- `j target`：函数内保留 `branch_j_target_<addr>` 作为目标，正常轮次使用
  短 `j`，对象检查确认越界后才经 `t0` 保存/恢复的内部长跳跳板；跨函数
  改成 `tail <func>_translated`；显式 `foo@plt` 目标先经 GOT 取址和 Runtime 查表，再执行间接尾调用；
- `jal x0,target`：函数内继续按显式链接寄存器语义改写，跨函数使用
  `tail <func>_translated`；本次自动本地长跳策略只覆盖 emitter 直接识别
  的本地 `j`，不扩展到其他控制流类别；
- `jal ra,target`、`call target`：跨函数使用 `call <func>_translated`；显式 `foo@plt` 目标先经 GOT 取址和 Runtime 查表，再执行间接调用；
- `jal rd,target` 且 `rd != ra,x0`：只改写目标，不改成普通 `call`，以免破坏自定义返回地址寄存器语义；
- `jal rd,foo@plt` 且 `rd != ra,x0`：当前明确生成 `ebreak` fallback，因为该形式不能直接套用标准 `call/tail` 的共享对象重定位约定；
- 带链接的 `jalr` 和 `ret`：沿既有 Runtime 调用/返回 ABI 查询目标后执行间接控制流。
- 无链接的 `jr` / `jalr x0`：查询返回原有效目标时，恢复全部现场后执行原指令；
  返回不同地址时，恢复现场后 `ebreak`。通用无链接重映射需要目标入口恢复跳板
  或 Runtime 配合，当前不能通过改写一个输入 GPR 来模拟。

### PLT 调用的目标转换

程序级显式 `call/jal/j/tail foo@plt` 不再直接进入动态链接器选定的函数。
发射器使用翻译 DSO 的 `R_RISCV_GOT_HI20` 引用取得函数地址，再调用现有
`query_original_translated_map(profile, address)`，最后用 `jalr ra` 或
`jalr x0` 保留普通调用或尾调用语义。PLT 桩本身仍不生成翻译体，原始
CFG 中的外部调用仍保持保守分析，不把桩当成有完整语义的内部函数。

程序级 objdump 解析必须保留 `.plt`、`.plt.sec`、`.plt.got` 等 PLT 段中的
`foo@plt` 条目，供地址索引使用；不能只读 `.text`。段切换时清除当前函数，
避免把新段的指令追加到前一个函数；PLT resolver 段头和数据段不作为普通函数
接收。片段解析接口仍只处理原有文本段。回归输入包含实际段标题、两种段排列
顺序，以及 `__kmpc_fork_call` / `__kmpc_barrier` 调用，防止无段标题的简化
样本掩盖生产输入的解析遗漏。

查询前保存易失整数寄存器、易失浮点寄存器和 `fcsr`；查询后恢复参数，
在最终调用前撤销临时栈帧，保留原有栈上传参位置。显式 PLT 调用的最终目标
占用标准调用约定中的易失寄存器 `t1`。同一套保护也用于回调 `jalr` 和
`ret` 的查询，避免破坏浮点参数与返回值；间接调用的基址从保存的寄存器
槽读取，避免被查询准备代码覆盖。该路径针对 RV64GC 标准标量调用约定，不声明支持
向量寄存器传参的 variant calling convention。生成的 Runtime 辅助调用直接
发射，不会递归经过此转换。

OpenMP 路径要求 `__kmp_invoke_microtask`、工作函数及相关算子的翻译体和
对应 offset map 已生成并注册；进入翻译 helper 后，内部回调复用既有
`jalr` 查表路径。Runtime 当前在正向映射缺失时返回原地址，因此修改调用点
不能保证所有热点已进入翻译版本，必须验证各工作线程的入口命中。

边界：GOT 引用遵循翻译 DSO 的符号查找范围，不保证与原始模块的符号版本、
局部绑定或独立加载命名空间等价。带版本等不支持形式的 PLT 符号明确生成
不支持诊断，而不是剥掉版本后查找同名函数。

相邻 `auipc` 加 `jalr/jr` 的情况由结构分析计算候选地址：要求地址连续、
AUIPC 目的寄存器与跳转基址一致，且符号索引中存在地址匹配的 PLT 桩。
不依赖 objdump 注释，也不把间接 CFG 边改成静态已解析边。发射器计算实际
寄存器目标、清除最低位，再与“原始模块基址 + 候选 PLT 地址”比较；仅匹配
时通过 GOT 解析函数地址，否则直接查询实际目标。这样保留任意迁移入口及
绕过 AUIPC 进入 JALR 的执行语义。非相邻、无法计算候选或缺少 PLT 符号的
间接调用仍走通用查询路径，不声明能解析所有动态计算出的 PLT 地址。

`tests/test_plt_target_lookup.py` 检查对象重定位，并可使用
`riscv64-elf-as/ld` 和 `qemu-system-riscv64` 执行双 profile 的普通调用、
尾调用及 helper/回调映射缺失测试。查询桩刻意破坏易失寄存器与浮点状态，
以验证参数、栈、浮点返回值和返回路径；还覆盖绕过 AUIPC、改变目标寄存器
后直接进入 JALR 的路径。`test_linux_shared_library_callback` 在 Linux/RV64
主机上构建实际共享回调库，验证 GOT、直接调用和 AUIPC/JALR 两种路径；
其他平台明确跳过此项。运行命令为：

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=.:src python3 -m pytest -q tests/test_plt_target_lookup.py
```

这些小型回调测试不等于实际 libomp、工作线程 TLS 或 llama.cpp 性能验证。

### 示例

输入：

```asm
38cce: 00090663             beqz    s2,38cda <foo+0xe>
38cd2: a021                 j       38ce2 <foo+0x16>
```

输出：

```asm
beqz     s2, branch_j_target_38cda
j        branch_j_target_38ce2
```

自定义 link register 的外部调用：

```asm
jal      t0, bar_translated
# 不支持 jal t0, memset@plt，生成 ebreak fallback
ebreak
```

程序模式本地 `j` 的 `R_RISCV_JAL`/RVC jump 范围修正已经收回到翻译器
目录内：正常轮次保留短跳，对象级检查确认越界的 site 才进入长跳轮次。
条件分支范围、`jal x0` 的其他形式，以及共享对象中跨函数直接
`jal *_translated` 的 PIC（位置无关代码）重定位问题仍需单独处理和使用
RISC-V 工具链验证，详见根目录 [`TRANSLATOR_ISSUES.md`](../TRANSLATOR_ISSUES.md)。
