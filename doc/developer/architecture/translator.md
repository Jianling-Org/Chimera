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
只存在于本轮 `EmissionSession`，不会写回准备结果。严格后端的 preflight
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
| `extensions/spacemit_ime/` | A100 IME 展开入口（`translation.py`、`backend.py`、`rearrange.py`、`block.py`） | 复用 `TranslationPipeline.prepare` 与同一 `HandlerRegistry` 合同，但**不**使用 `simulated_cpu_state` 布局 |

完整 pipeline 和 ProgramEmitter 是当前 RVV 场景的组合者。扩展点首先体现在
共用程序处理能力可以独立使用，尚未建立多扩展自动注册和组合框架。

`extensions/spacemit_ime/` 是仓库内第二个扩展命名空间：它把 IME 指令展开为
原生 RVV1024，源和目标都用 A100 向量寄存器布局，用物理寄存器栈帧而非
`simulated_cpu_state` 保存借用状态，也不生成 offset map。它不改变上面三条
RVV 路径的方向几何、状态布局或验证结论；细节和已披露限制见
[IME_RVV.md](../translator/ime-rvv.md)。

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
- `src/riscv/extensions/rvv/analysis/model.py`、`src/riscv/frontend/model.py`：只保存结构化分析结果，不生成后端汇编。

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

`ControlFlowEmitter` 负责源地址标签、直接/间接控制转移和 PLT 目标处理。`branch_j_target_<addr>` 保留精确源地址身份，不能将内部目标替换为函数入口。

- 函数内条件分支与直接跳转绑定到地址标签；普通本地 `j` 在对象级检查确认越界后才使用保存/恢复寄存器的长跳跳板。
- 已解析的跨函数调用使用 `<name>_translated`；无链接跨函数跳转使用保持寄存器现场的跳板，不能用会破坏临时寄存器的 `tail` 无条件替换。
- 自定义链接寄存器必须保持源 `rd` 语义；不支持的 PLT 形式明确拒绝。
- 无链接 `jr`、`jalr x0` 与 `ret` 只接受 identity 查询结果；非 identity 恢复现场后执行 `ebreak`，不通过改写只读源寄存器转移。
- AUIPC/JALR PLT 路径根据已解析 GOT 槽读取实际目标，再调用 Runtime 地址查询。无法识别的 PLT 输入不能猜测目标，查询返回零时终止相应路径。

控制流查询需保护调用者 GPR、FPR、fcsr 与栈；对象范围检查、运行期地址查询和最终 offset map 是不同阶段。相关回归包括 `test_program_contract.py`、`test_control_flow_review_fixes.py`、`test_plt_target_lookup.py` 和 `test_translated_symbol_binding.py`。

## 共享对象链接

翻译函数定义使用 `.protected`，使库内引用绑定到当前翻译库自身，避免全局同名符号抢占。跨函数调用使用 `call`；可能被外部抢占的符号不能随意使用直接 `R_RISCV_JAL` 重定位。

`test_translated_symbol_binding.py` 检查 `FUNC/GLOBAL/PROTECTED` 属性以及内部函数没有 `R_RISCV_JUMP_SLOT` 项。对象检查需要目标工具链，部分动态加载用例还需要 Linux ELF 动态加载器。

更新翻译汇编后，重新构建 DSO 并按最终链接地址生成 offset map。对象链接、动态加载、PLT/IFUNC、线程 TLS 和实际迁移分别验证；局部链接检查不能替代目标平台运行。支持边界见[当前限制](../translator/limitations.md)。
