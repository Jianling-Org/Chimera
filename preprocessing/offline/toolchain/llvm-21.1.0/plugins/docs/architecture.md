# Chimera LLVM 集成架构

## 1. 工程形态

`chimera/preprocessing/offline/toolchain/llvm-21.1.0/` 是一个独立的 CMake project，构建三个互相独立的 LLVM pass plugin，并携带一份按顺序应用到 LLVM 源码的 patch series。

```text
chimera/preprocessing/offline/toolchain/llvm-21.1.0/
├── CMakeLists.txt
├── common/
│   └── PCSectionsMeta.*
├── plugins/
│   ├── stackobject/          # ChimeraStackObject
│   ├── svf/                  # ChimeraFunctionPointer
│   └── vector_gate/          # ChimeraVectorGate
├── tests/
│   ├── stackobject/
│   └── svf/
├── patches/
└── docs/
```

三个 plugin：

| Plugin | CMake target | 选项 | 依赖 |
|---|---|---|---|
| `ChimeraStackObject` | `ChimeraStackObject` | `CHIMERA_ENABLE_STACKOBJECT` | LLVM 21.1.0、`ChimeraCommon` |
| `ChimeraFunctionPointer` | `ChimeraFunctionPointer` | `CHIMERA_ENABLE_SVF` | LLVM 21.1.0、`ChimeraCommon`、SVF |
| `ChimeraVectorGate` | `ChimeraVectorGate` | `CHIMERA_ENABLE_VECTOR_GATE` | LLVM 21.1.0 |

`common/` 构建为内部 PIC static library `ChimeraCommon`，仅供需要它的 plugin 共用，不单独安装。

**模块边界（强约束）**

- StackObject 不依赖 SVF：关闭 `CHIMERA_ENABLE_SVF` 时不进入 `plugins/svf/`，也不执行 `find_package(SVF)`。
- SVF 是可选组件。
- 三个 plugin 可以单独构建，也可以同时构建。
- 不要合并成一个 plugin，也不要让 StackObject 依赖 SVF。

---

## 2. 三个功能

本工程最终产出三个相互独立的功能：

| 功能 | 归属 | 目标 |
|---|---|---|
| `stack-object-id` | `ChimeraStackObject` + RISC-V backend patch | 把最终 RVV 内存指令的 linked VA 映射到 `StackObjectID` |
| `function-svf` | `ChimeraFunctionPointer` | 把 indirect call 的 linked VA 映射到可能的目标函数 linked VA |
| `vector-gate` | `ChimeraVectorGate` | 阻止名单函数的隐式向量化，并记录形成/阻止 census |
| `spill-cost` | LLVM vectorizer patch（`-spill-cost`） | 拒绝预计会导致 vector register spill 的 vectorization candidate |

三个插件彼此独立：只使用 StackObject 不需要 SVF；`-spill-cost` 是 LLVM
内建 patch 功能，不需要任何 Chimera plugin。

---

## 3. PCSections 是唯一 backend carrier

Chimera 信息的最终 transport **只有 LLVM PCSections**。数据从 IR plugin 出发，最终以 ELF section 形式落地：

```text
IR Plugin
   → IR metadata（!pcsections 或 !chimera.pcsections）
   → SelectionDAG / MachineInstr PCSections
   → AsmPrinter
   → ELF
```

backend 自行生成的 RVV spill/reload 直接在 `MachineInstr` 上附加 PCSections，不经过 IR plugin。

### 3.1 deferred metadata（staging carrier）

普通 IR 指令走 LLVM 原生的 `!pcsections` 传播。但有两类 IR 指令无法通过普通 `NodeMap` 可靠地定位到最终 SDNode：

- void `inline asm` 调用；
- `call` / `tail call`。

对这两类，plugin 使用 `!chimera.pcsections` 作为**临时 staging carrier**：

```text
IR !chimera.pcsections
   → SelectionDAGBuilder::visitInlineAsm()   （inline asm）
   → RISCVTargetLowering::LowerCall()        （CALL/TAIL）
   → DAG.addPCSections(exact SDNode)
   → MachineInstr PCSections
```

`!chimera.pcsections` 只在 SelectionDAG 阶段被消费，一旦进入 SDNode / MachineInstr 就只使用标准 PCSections。它不是第二套最终 transport。

`common/PCSectionsMeta.cpp` 提供两个 helper：

- `addOrMergePCSection()`：写 `!pcsections`，用于 RVV intrinsic 等可正常传播的指令。
- `addOrMergeDeferredPCSection()`：写 `!chimera.pcsections`，用于 inline asm 和 call/tail。

两者都保证 top-level `MDNode` 为 `distinct`，并且对同一指令只合并、不覆盖已存在的同名 section。

---

## 4. stack-object-id

### 4.1 目标

把最终 RISC-V RVV 内存指令的 **linked virtual address** 映射到 `StackObjectID`，供运行时识别某条 RVV 内存访问命中的栈对象。

覆盖三类来源：

1. LLVM RVV intrinsic（`llvm.riscv.vle` / `vle_mask` / `vse` / `vse_mask`）；
2. inline asm 中的 RVV memory instruction；
3. LLVM backend 自动生成的 RVV spill/reload。

最终输出 section：`.chimera.stackobj_map`。

### 4.2 wire format

Chimera 当前只支持 RV64，wire format 固定，**必须按 bytes 解析**（不使用 C struct padding 语义）：

```text
offset 0 : u64 LinkedVA
offset 8 : u32 StackObjectID
```

每条 record 恰好 12 bytes。记录顺序不是语义的一部分；测试按 `(LinkedVA, SOID)` 集合比较。

### 4.3 StackObjectID 编码

`SOID` 是 **function-local** identity，实际身份是 `(Function, SOID)`。

- IR/plugin 产生的显式 `StackObjectID`：`0x00000000 … 0x7fffffff`。同一个 `(AllocaInst, 常量 offset)` 得到同一个 SOID；intrinsic 与 inline asm 共享同一 registry。
- backend spill/reload：`SOID = 0x80000000 | FrameIndex`，合法 `FI ∈ [0, 0x7ffffffe]`。同一个 FI 的 spill 与 reload 使用同一个 SOID；不同 FI 使用不同 SOID。
- `0xffffffff` 保留为 invalid。

backend SOID 编码的是 **stack slot**，不是 spill event；stack-slot coloring 复用同一 FI 时视为同一个 final machine stack object（有意行为）。

### 4.4 backend per-Function opt-in gate

backend 生成的 spill/reload 相关行为由 string function attribute

```text
"chimera-stack-object"
```

进行 per-Function gating。`StackObjectPass` 在通过 `riscv64` triple + 64-bit 默认指针检查后，**总是**为该 Function 添加该 attribute（即使 IR 中没有已识别的 stack access，因为 backend spill 可能之后才产生）。

只有存在该 attribute 时：

- ordinary RVV spill/reload 才附加 `.chimera.stackobj_map!A`；
- tuple RVV spill/reload child 才传播 Chimera PCSections；
- Chimera 的 RV64 / FI / SOID 检查才执行。

没有该 attribute 时，patched LLVM 保持 upstream RISC-V codegen 行为：stock RV32/RV64 spill/reload 照常生成，但不产生 Chimera PCSections、不触发 Chimera 的 RV64-only fatal、不产生 `.chimera.stackobj_map`。

该 gate 使 stock LLVM 在未启用 Chimera attribute 时保持原有行为；具体回归结果以当前 runner 输出为准。

### 4.5 RV64 限制的归属

- **Generic** PCSections `!A` 按 target pointer size 发 symbol value（RV64 8 bytes、RV32 4 bytes），不是 Chimera 专属，不限于 RV64。
- **RV64-only** 是 Chimera StackObject feature 的限制：`StackObjectPass` 在 IR 侧检查 `riscv64` triple + 64-bit 指针；backend 在 attribute gate 内检查 `XLEN == 64`。

---

## 5. function-svf

### 5.1 目标

使用 SVF Andersen 指针分析处理 indirect call：

```text
indirect call linked VA
   →
possible target function linked VAs
```

接受 false positive；不接受 false negative。不引入 FID / CSID / BasicBlock-order matching 等旧方案。

### 5.2 pipeline

`FunctionPointerPass` 是一个 module pass，注册在 Full-LTO last EP：

```text
收集原 module 的 indirect callsite
   → CloneModule（SVF 只能操作 clone，不能操作进入 CodeGen 的 module）
   → LLVMModuleSet::buildSVFModule
   → SVFIRBuilder::build
   → AndersenWaveDiff（disablePrintStat + analyze）
   → 对每个原 callsite：getIndCSCallees → 映射回原 Function
   → 附加 .chimera.function_pointer!A
```

### 5.3 wire format

最终 section：`.chimera.function_pointer`。

```text
resolved:
  offset 0 : u64 call LinkedVA
  offset 8 : u32 target_count
  offset 12: u64 target LinkedVA × target_count

unresolved:
  offset 0 : u64 call LinkedVA
  offset 8 : u32 0
```

`target_count == 0` 表示该 callsite 的 function-pointer 分析不可用或不完整。目标函数按名称排序输出，保证确定性。

以下情况判为 unresolved（绝不输出部分结果）：

- 找不到 clone 后的对应 `CallBase`；
- SVF 没有该 callsite 的 `CallICFGNode`；
- Andersen 没有非空 target set；
- 任一 target 无法映射回原 Function；
- target 是 external declaration（当前 ELF 中没有其函数体地址）。

### 5.4 extapi.bc

`plugins/svf/resources/extapi.bc` 与插件版本、LLVM/SVF 版本绑定，构建与安装后都位于插件旁。插件运行时通过 `dladdr` 定位自身，读取同目录的 `extapi.bc`。若不可用，插件不中止编译，而是把每个 indirect callsite 标为 unresolved 并输出 warning。

### 5.5 链接约束

SVF 通过 static archive 链接进 `ChimeraFunctionPointer.so`：

- 允许动态依赖 `libLLVM.so.21.1`；
- 不允许动态依赖 `libSvfLLVM.so` / `libSvfCore.so`。

`SVF::SvfLLVM` 的导出目标带有 LLVM 传递链接项。构建时保留静态 SVF 库，移除这些传递项，并由 LLVM pass-plugin 构建规则链接当前工具链的 LLVM 依赖，避免在插件中再链接另一份 LLVM。

---

## 6. spill-cost

LLVM 新增隐藏选项 `-spill-cost`（默认关闭），同时作用于 Loop Vectorizer 与 SLP Vectorizer。它拒绝预计会导致 vector register spill 的 vectorization candidate，**不是**“禁止所有 spill”，也不影响用户手写 intrinsic 的 backend register allocation。

### 6.1 Loop Vectorizer

复用已有 VPlan register usage 分析，但新增 `VPRegisterUsage::exceedsMaxNumVectorRegs()`：只统计 vector register class，当 candidate 的 vector register pressure 超出 target 的 vector register 数量时拒绝该 VF。GPR/FPR pressure 超限不触发本 gate；LLVM 原有 `max-bandwidth` 的 `exceedsMaxNumRegs()` 行为不变。

### 6.2 SLP Vectorizer

LLVM 21.1 没有与 LV 等价的完整 SLP register-pressure estimator。当前实现使用 LLVM 原生 `BoUpSLP::getSpillCost()`：

> 若 vector values live across 未被向量化的 call，且 LLVM 原生 spill predictor 得到正的 spill cost，则在 `-spill-cost` 下拒绝该 SLP tree。

### 6.3 非对称实现（有意设计）

| Vectorizer | 判定方式 |
|---|---|
| Loop Vectorizer | VPlan vector-register pressure gate |
| SLP Vectorizer | LLVM-native live-over-call spill predictor |

不要声称 SLP 已有完整 register-pressure model。

---

## 7. Stack address classifier

`StackAddrKind` 有四种取值：

| 取值 | 语义 | 行为 |
|---|---|---|
| `ExactStack` | 唯一可能位置，且可证明是当前 Function 的 local alloca，offset 为常量 | 创建/查询 SOID，生成 metadata |
| `ProvenNotCurrentLocalAlloca` | 唯一位置，但可证明不是当前 Function 的 local alloca（global / argument 等） | 静默忽略 |
| `MultipleLocations` | 存在多个可能位置（不止一个） | 静默忽略，不 warning |
| `UnknownProvenance` | 未发现多个位置，但无法证明是否属于当前 Function 栈 | warning + 忽略 |

关键区别：

- `MultipleLocations` 指“存在多个可能位置”，不是“多个 stack location”；无论组合为 stack+stack、stack+global 等都归为 `MultipleLocations`，且**不应**被误 warning 成 unknown provenance。
- 只有 `ExactStack` 才生成 SOID。
- `ProvenNotCurrentLocalAlloca` 可静默忽略。
- `UnknownProvenance` 代表存在单一抽象来源但无法证明为当前 local stack。

---

## 8. inline asm 支持规则

inline asm 分析针对整个 asm block：

- 先扫描整个 block，统计 RVV memory instruction 数量：
  - 0 个 → 忽略整个 asm；
  - 多于 1 个 → `UnsupportedRelevant`，warning 并忽略。
- 若恰好 1 个目标：
  - 其余实际 instruction 只能属于 scalar address-calculation whitelist（`nop`、`mv`、`addi`）；
  - control-flow、额外 vector instruction、未知语义均禁止；
  - 不允许可能展开成多条 MCInst 的 pseudo（例如 `li`）。
- instruction index 是 actual instruction 的 zero-based index；label 与 `.option` 等 directive 不计入。
- 地址表达式必须能解析为 `CallBase 参数 + 常量 offset`（或从 `zero`/常量地址证明非栈）；无法解析时按当前代码行为 warning/ignore，而不是猜测。

最终 inline asm 的 PCSections 使用 `.chimera.stackobj_map!AL`，aux payload：

```text
aux[0] = target instruction index
aux[1] = SOID
```

`L` locator 只在 backend 使用，不进入最终 wire format。AsmPrinter 把 label 放到目标 RVV memory instruction 正前方，使 LinkedVA 精确对应目标 instruction 而不是整个 inline asm block 起始地址。

---

## 9. 关键 invariant

- 最终 carrier 只有 PCSections；`!chimera.pcsections` 只是 deferred staging。
- `.chimera.stackobj_map` 每条 12 bytes，`[u64 LinkedVA][u32 SOID]`，按 bytes 解析。
- 记录粒度是每条 MachineInstr 一条（0008 在 `AsmPrinter::emitPCSectionsLabel()` 强制）：一条 IR 指令被 SelectionDAG 展开成多条 MI、或被 LTO 期 inline/unroll 克隆时，共享 node 的多个 PC 必须各成一条记录，不得按 upstream 语义聚成"N 个 PC + 一次 aux"——那会破坏 12 字节步长。
- LinkedVA 是 final linked absolute address，不是 relative/PC-relative/symbol delta。
- SOID 是 function-local identity；backend spill 使用 `0x80000000 | FI`，`0xffffffff` invalid。
- 每条最终 instruction 的 top-level PCSections `MDNode` 必须 distinct（aux 可共享）。
- `.chimera.*` PCSections section 只保留 `SHF_LINK_ORDER`，不设置 `SHF_WRITE | SHF_ALLOC`。
- backend spill/reload 行为由 `"chimera-stack-object"` attribute gate；stock codegen 保持不变。
- StackObject 不依赖 SVF。
- `-spill-cost` 只 gate vector register pressure（LV）或原生 spill cost（SLP），不禁止所有 spill。
