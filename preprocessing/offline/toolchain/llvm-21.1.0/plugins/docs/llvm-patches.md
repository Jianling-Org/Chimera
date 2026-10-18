# LLVM 21.1.0 Patch Series

本目录中的补丁仅针对干净的 LLVM `llvmorg-21.1.0`，必须按文件名前缀顺序应用。十二个补丁是依赖有序的 concern series；不得跳号、并行应用或把职责重新合并。

## 0001：PCSections absolute `!A`

文件：`0001-PCSections-support-absolute-PC.patch`

- 在 `AsmPrinter` 中解析 `!A`；
- 使用当前 target pointer size 发出 instruction symbol value；
- 不包含 Chimera-specific section flags 或 RV64 限制；
- lit：`llvm/test/CodeGen/Generic/pcsections-absolute.ll` 使用 `riscv64` / `riscv32`，同时检查 64-bit `.quad` 和 32-bit `.word`；不需要 X86 backend。

本补丁是后续 absolute map 的基础，无前置依赖。

## 0002：PCSections inline-asm locator `!L`

文件：`0002-PCSections-support-inline-asm-locator.patch`

- 增加 `!L` locator 解析、内部 label 插入和 locator auxiliary 消费；
- 保留同一 INLINEASM 上非 `!L` PCSections 的普通语义；
- 在 `SelectionDAGBuilder::visitInlineAsm()` 把 `!chimera.pcsections` 转移到 exact `INLINEASM` / `INLINEASM_BR` SDNode；
- lit：`llvm/test/CodeGen/RISCV/chimera-pcsections-inline-asm.ll` 检查 label 位于目标内部指令，locator 不进入最终 payload。

依赖 0001 的 PCSections option/emission 路径。

## 0003：`.chimera.*` ELF section flags

文件：`0003-Chimera-ELF-section-flags.patch`

- 只修改 `MCObjectFileInfo::getPCSection()` 的 section flag policy；
- `.chimera.*` 保留 `SHF_LINK_ORDER`，不设置 `SHF_WRITE | SHF_ALLOC`；
- 普通 PCSections flags 不变；
- lit：`llvm/test/CodeGen/Generic/chimera-pcsections-flags.ll` 使用 `riscv64` 同时检查 Chimera 和 ordinary section，不需要 X86 backend。

依赖 0001；与 inline-asm locator、RISC-V spill 逻辑解耦。

## 0004：RISC-V ordinary RVV spill/reload

文件：`0004-RISCV-ordinary-RVV-spill-StackObject-PCSections.patch`

- 仅当 Function 带 `"chimera-stack-object"` attribute 时，在
  `RISCVInstrInfo` 创建普通 RVV spill/reload 后附加
  `.chimera.stackobj_map!A`；
- 无 attribute 的 stock RV32/RV64 codegen 不进入 Chimera XLEN、FI、SOID
  或 PCSections 逻辑；spill/reload 本身仍照常生成；
- SOID 保持 `0x80000000 | FI`，`0xffffffff` 仍为 invalid；
- 同一 FI 的 spill/reload 使用同一 SOID，不同 FI 使用不同 SOID；
- 只标记 compiler-created spill/reload，不标记无关 RVV memory operation；
- attribute gate 内、创建 Chimera backend map metadata 前明确检查
  `getXLen() == 64`；
- positive lit：`chimera-rvv-spill.ll` 显式带 attribute，覆盖 VR、VRM2、
  VRM4、VRM8 和无关 RVV op；
- stock negative lit：`chimera-rvv-spill-stock-rv64.ll` 与
  `chimera-rvv-spill-stock-rv32.ll` 强制产生 RVV spill/reload，同时禁止
  Chimera PCSections/section；RV32 必须正常 codegen；
- Chimera negative lit：`chimera-rvv-spill-rv32.ll` 显式带 attribute，保留
  RV32 XLEN fatal diagnostic。

依赖 0001 和 0003；不依赖 tuple propagation。

## 0005：RISC-V tuple spill child propagation

文件：`0005-RISCV-tuple-spill-PCSections.patch`

- tuple spill/reload pseudo expansion 始终执行；仅带
  `"chimera-stack-object"` attribute 时读取和传播其 PCSections；
- 为每个真实 memory child clone distinct top-level MDNode；
- 不给地址计算 ADD 或无关 RVV memory op 附加 metadata；
- pseudo 删除后不保留 stale record；
- positive MIR lit：`chimera-rvv-tuple-spill.mir` 显式带 attribute，检查
  7 store + 7 load children、pseudo 消失以及 ADD/无关 op 不带 PCSections；
- stock negative MIR lit：`chimera-rvv-tuple-spill-stock.mir` 不带
  attribute，检查 pseudo 仍展开为 7+7 children，但 child/final asm 没有
  Chimera PCSections 或 section。

依赖 0004，因为 tuple pseudo 的初始 backend SOID/PCSections 由 0004 创建。

## 0006：RISC-V deferred CALL/TAIL PCSections

文件：`0006-RISCV-deferred-CALL-TAIL-PCSections.patch`

- 只修改 `RISCVTargetLowering::LowerCall()`；
- 把 callsite 的 `!chimera.pcsections` 转移到 exact CALL 或 TAIL SDNode；
- 不包含 `SelectionDAGBuilder::visitInlineAsm()` 修改；该职责已属于 0002；
- lit：`chimera-pcsections-call-tail.ll` 检查 CALL、TAIL label 和各自 auxiliary payload。

依赖 0001 和 0003；与 spill patches 的实现逻辑独立，但在 series 中固定排在它们之后。

## 0007：Loop/SLP `-spill-cost`

文件：`0007-Vectorizers-reject-vector-register-spills.patch`

- 增加共享隐藏选项 `-spill-cost`，默认关闭；
- Loop Vectorizer 只用 vector register class pressure 拒绝候选，不把 GPR-only pressure 当作本 gate；
- 保留 `max-bandwidth` 原有 `exceedsMaxNumRegs()` 行为和 debug 输出不变；
- SLP 复用 `BoUpSLP::getSpillCost()`：正 spill cost 时拒绝，zero cost 仍允许；
- lit：`LoopVectorize/RISCV/spill-cost.ll` 覆盖 OFF/ON（真实 vector pressure，不含无意义的 `-force-target-num-*-regs`）；
- unit test：`unittests/Transforms/Vectorize/VPlanAnalysisTest.cpp` 直接验证
  `VPRegisterUsage::exceedsMaxNumVectorRegs()` 只检查 vector register class，
  不因 scalar/GPR register class 超限返回 true（GPR-only 无法在 VPlan 中稳定构造，故用 unit test 覆盖）；
- lit：`SLPVectorizer/spill-cost.ll` 覆盖 positive spill OFF/ON 和 zero spill ON。

本补丁不依赖 PCSections，但固定为 series 最后一项。

## 0008：AsmPrinter 每 MachineInstr 一条 Chimera 记录

文件：`0008-AsmPrinter-one-Chimera-PCSections-record-per-MI.patch`

- 修复 2026-08-27 llama.cpp 端到端首跑暴露的 `.chimera.stackobj_map`
  尺寸非 12 字节倍数问题（`chimera: error: .chimera.stackobj_map size is
  not a multiple of 12 bytes`）：upstream PCSections 发射把共享同一
  metadata node 的所有 MachineInstr PC 聚成一个条目（N×pointer-size
  之后只发一次 aux），与 Chimera 固定 `[u64 PC][u32 SOID]` 记录布局冲突；
- 一个 node 合法地对应多条 MI 有两条途径：SelectionDAG 把一条 IR 指令
  展开成多条 MI（`store volatile` 的常量物化即产生 li+sw 两条）；LTO
  链接期 inline/unroll 克隆的指令保留原 node。插件 per-instruction
  distinct 节点只防住 metadata uniquing，防不住这两条；
- 修复：`AsmPrinter::emitPCSectionsLabel()` 检测 node 引用 `.chimera.*`
  节时，为每次调用（即每条 MI）注册一个 fresh distinct 副本；每个条目
  恰含一个 PC，记录恒为 8+4 字节。同时覆盖 `.chimera.call_targets`
  （function_pointer 同构风险）；非 Chimera 节保持 upstream 分组语义；
- lit：`llvm/test/CodeGen/Generic/chimera-pcsections-per-mi-records.ll`
  用共享 `!0` 的两条 store（各展开为 li/sw 两条 MI）验证四条
  `.quad`+`.word` 交替记录；未修复的分组形状会使 CHECK-NEXT 失败；
- 插件侧端到端回归：`tests/stackobject/shared-node.ll` + run.sh 末尾
  新增 llc→lld→check_stackobj_map.py 用例（三条 store 共享一个 node、
  六条 MI；未修复时 6×8+4=52 字节直接触发 size 非 12 倍数错误）。

依赖 0001/0002（改动位于其插入的 helper 之后）；0003–0007 不触碰
AsmPrinter.cpp，故 series 顺序上固定为最后一项。

状态：2026-08-27 新增。`git am` 干净应用性已对照 llvmorg-21.1.0 + 0001
+ 0002 后的 AsmPrinter.cpp 精确验证；服务器侧 patched-llvm 重建、lit
  与端到端复验待执行。

## 0009：`chimera-no-vectorize` auto-vectorization gate（基础语义）

文件：`0009-chimera-vectorizer-guards-and-census.patch`

- 新 per-Function attribute `"chimera-no-vectorize"` 是 auto-vectorization
  gate 的唯一开关（不做 target-feature 剥离，含 RVV intrinsics/inline asm
  的函数同样被 gate）；
- `InlineFunction` 只拒绝 gated callee 合并进 ungated caller，防止受保护
  函数体逃逸；ungated callee 合并进 gated caller 允许，caller 仍由函数级
  vectorizer gate 保护。该方向保持非 LTO gate 路线的 discovery 函数拓扑；
- `LoopVectorizePass::run()` 与 `SLPVectorizerPass::run()` 对 gated
  function 在形成任何向量代码前 early-out（返回
  `PreservedAnalyses::all()`）；
- 统计实现由 0012 统一：只在 LV/SLP 的最终正向决策点记录严格的
  `implicit-vector-census<TAB>机制<TAB>函数<TAB>formed|blocked` 行；
  0009 中的函数入口保护仅是基础 gate 语义，不能作为统计分母。
- lit：`Transforms/Inline/chimera-no-inline-gate.ll`（四种 caller/callee
  方向）、`Transforms/LoopVectorize/chimera-no-vectorize-gate.ll`
  （gated 保持标量，对照函数出现 `vector.body`）。

不触碰 0001–0008 的文件（0007 同改 Loop/SLP 但位于不同区域），语义上
是 0010/0011 所用 attribute 的定义点。

> 0012 会把 gate 从函数入口保护细化到最终正决策提交点，并删除旧的
> `vectorizer-census`、`memop-census`、`merge-census` 事件格式；最终统计
> 口径以 0012 和 `vector_census_report.py` 为准。

## 0010：RISC-V memop 向量展开的 gate 抑制

文件：`0010-RISCV-suppress-vector-memop-expansion-under-gate.patch`

- `RISCVTargetLowering::getOptimalMemOpType()` 对 gated function 返回
  `MVT::Other`，迫使常量长度 memcpy/memset 走标量展开或 libcall，而非
  VLEN 敏感的向量访存序列（whole-register `vs2r.v`/`vl2r.v`、fixed-vl
  `vse`，其字节范围随 VLEN 变化）；
- 0012 将 census 接到同一最终决策接口：门在形状/合法性检查之后生效，
  只有本来会形成向量类型的查询记录 `MEMOP formed|blocked`，并通过
  late function ID 归属到函数；旧的无函数名 `memop-census` 仅保留在
  本补丁的历史 diff 中。
- includes：`FileSystem.h`（`sys::fs::OF_Append`，21.1.0 无 `CD_Append`
  枚举；`OF_Append` 经 `nativeOpenFlags()` 强制 `CD_OpenAlways` +
  `O_APPEND`，即不存在则创建、存在则追加，不截断）与 `<cstdlib>`。

依赖 0009（attribute 语义由其引入）。

## 0011：DAGCombiner store merging 的 gate 抑制

文件：`0011-codegen-suppress-vector-store-merging-under-gate.patch`

- `DAGCombiner::mergeConsecutiveStores()` 在 gated function 上保持
  `AllowVectors = false`，合并结果停留在标量（宽整数或逐元素）形态，
  不再映射为 VLEN 敏感的向量 store；标量宽合并本身不受影响；
- **门控漏洞修复**：`tryStoreMergeOfExtracts`（提取向量元素合并为
  单个向量 store 的路径）upstream 从不查询 `AllowVectors`，门控下
  原本仍会生成向量 store。现为其传入 `AllowVectors` 并在提交点拒绝
  ——gated function 的标量 store 保留（仅 gated codegen 变化，stock
  行为不变；NoImplicitFloat-only 函数不受影响，该路径 upstream 本就
  不查 `AllowVectors`）；
- 0012 将 constants、loads、extracts 三条路径接到统一 census 接口，
  只统计最终正向 vector merge；gated 下记录反事实 `blocked` 并保留
  scalar stores。旧的 `merge-census` 事件格式不再是正式输出。
- includes：`FileSystem.h` 与 `<cstdlib>`。

依赖 0009。

## 0012：单面、函数级隐式向量决策 census

文件：`0012-chimera-single-face-implicit-vector-census.patch`

- 新增 header-only `ChimeraImplicitVectorCensus.h`，统一输出：
  `implicit-vector-census<TAB>LV|SLP|MEMOP|MERGE<TAB>规范化函数名<TAB>formed|blocked`；
- LV 覆盖普通与 VPlan-native 路径，只在 VF/成本正决策成立且首次
  `executePlan()` 前记录；scalar interleave、loop simplify、LCSSA 不计入；
- SLP 覆盖 store tree、普通 list、horizontal reduction 三个顶层
  `vectorizeTree()` 提交点；
- MemOp 通过优化末尾写入的 `chimera-census-function-id` 获得函数身份；
  census 开启但 ID 缺失时编译立即失败；
- Store Merge 的 constants、loads、extracts 三条路径均在最终向量决策处
  记录并拒绝；`NoImplicitFloat` 自身造成的拒绝不归因于 gate；
- `formed` 与 `blocked` 都只表示正向量决策；gated 函数若越过拒绝分支到达
  commit 会触发 fatal error，不设置“命中但仍生成”统计项。

构建脚本只解析一次干净、全量 gate census。各机制按函数集合去重，总计按
四类机制函数并集去重；显式 RVV intrinsic/builtin/inline asm 不会让函数从
分母排除。

## 应用

```bash
git checkout llvmorg-21.1.0
PATCH_DIR=/path/to/chimera/preprocessing/offline/toolchain/llvm-21.1.0/patches
git am "$PATCH_DIR"/*.patch
```

（`chimera-dev toolchain build patched-llvm` 实际按 `patches/*.patch` 排序
glob 应用，全部十二个补丁会被自动纳入。）

应用失败时先定位原因，再执行 `git am --abort`；不得跳过失败补丁继续。

## 验证

推荐从干净 baseline 创建专用 worktree 后运行：

```bash
git diff --check llvmorg-21.1.0..HEAD
ninja -C /path/to/llvm-build check-llvm
```

也可只执行本 series 新增的 lit tests：

```bash
llvm-lit -v \
  llvm/test/CodeGen/Generic/pcsections-absolute.ll \
  llvm/test/CodeGen/Generic/chimera-pcsections-flags.ll \
  llvm/test/CodeGen/RISCV/chimera-pcsections-inline-asm.ll \
  llvm/test/CodeGen/RISCV/chimera-rvv-spill.ll \
  llvm/test/CodeGen/RISCV/chimera-rvv-spill-stock-rv64.ll \
  llvm/test/CodeGen/RISCV/chimera-rvv-spill-stock-rv32.ll \
  llvm/test/CodeGen/RISCV/chimera-rvv-spill-rv32.ll \
  llvm/test/CodeGen/RISCV/chimera-rvv-tuple-spill.mir \
  llvm/test/CodeGen/RISCV/chimera-rvv-tuple-spill-stock.mir \
  llvm/test/CodeGen/RISCV/chimera-pcsections-call-tail.ll \
  llvm/test/CodeGen/Generic/chimera-pcsections-per-mi-records.ll \
  llvm/test/Transforms/LoopVectorize/RISCV/spill-cost.ll \
  llvm/test/Transforms/SLPVectorizer/spill-cost.ll \
  llvm/test/Transforms/Inline/chimera-no-inline-gate.ll \
  llvm/test/Transforms/LoopVectorize/chimera-no-vectorize-gate.ll
```

最终 linked VA、固定 12-byte map 和 final relocation 状态继续由 Chimera integration tests 验证，不强塞入 LLVM lit。CALL/TAIL deferred transfer 的 lowering 层行为由 `chimera-pcsections-call-tail.ll` 负责；SVF integration 只检查 plugin 生成的 resolved/unresolved map 和最终 ELF。

## 可复现性

从干净的 `llvmorg-21.1.0` 开始，按文件名前缀顺序执行上面的 `git am`，
然后运行 `git diff --check` 和需要的 LLVM lit/integration 测试。测试结果、
工具链提交和构建参数应随实验日志保存；不要在文档中固定某次机器的测试数量或
验收结论。
