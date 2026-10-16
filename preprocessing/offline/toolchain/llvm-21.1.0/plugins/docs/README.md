# Chimera LLVM 集成工程

`chimera/preprocessing/offline/toolchain/llvm-21.1.0` 是 Chimera 的统一 LLVM 21.1.0 扩展工程：一份共享实现、三个可独立启用的插件，以及一套按顺序应用到 LLVM 源码的 patch series。

## 功能与产物

Chimera 需要三类信息，本工程分别产出：

| 功能 | 实现 | 目标 |
|---|---|---|
| `stack-object-id` | `ChimeraStackObject` 插件 + RISC-V backend patch | 把最终 RVV 内存指令的 linked VA 映射到 `StackObjectID` |
| `function-svf` | `ChimeraFunctionPointer` 插件（SVF Andersen） | 把 indirect call 的 linked VA 映射到可能的目标函数 linked VA |
| `vector-gate` | `ChimeraVectorGate` 插件 | 按函数名单阻止隐式向量化并输出 census |
| `spill-cost` | LLVM vectorizer patch（`-spill-cost`） | 拒绝预计会导致 vector register spill 的 vectorization candidate |

三个插件彼此独立：只使用 StackObject 不需要 SVF；`-spill-cost` 是 LLVM
内建 patch 功能，不需要任何 Chimera 插件。

## 三个插件

- `ChimeraStackObject`：LLVM-only，CMake 选项 `CHIMERA_ENABLE_STACKOBJECT`，pass 名 `chimera-stack-object`。
- `ChimeraFunctionPointer`：依赖 SVF，CMake 选项 `CHIMERA_ENABLE_SVF`，注册在 Full-LTO last EP。
- `ChimeraVectorGate`：LLVM-only，CMake 选项 `CHIMERA_ENABLE_VECTOR_GATE`，按
  `CHIMERA_GATE_LIST` 阻止隐式向量化并可写入 `CHIMERA_GATE_STATS` census。

`common/` 构建为内部静态库 `ChimeraCommon`，需要它的插件共用，不单独安装。
StackObject 和 VectorGate 不依赖 SVF；三个插件可单独或同时构建。

## 目录结构

```text
chimera/preprocessing/offline/toolchain/llvm-21.1.0/
├── CMakeLists.txt
├── common/                 # ChimeraCommon（PCSectionsMeta.*）
├── plugins/
│   ├── stackobject/        # ChimeraStackObject
│   ├── svf/                # ChimeraFunctionPointer（仅此插件依赖 SVF）
│   └── vector_gate/         # ChimeraVectorGate
├── tests/
│   ├── stackobject/
│   ├── svf/
│   └── tools/
├── patches/                # 按文件名排序的 LLVM patch series
└── docs/
```

## 整体数据流

IR plugin 通过 PCSections（或临时的 `!chimera.pcsections` deferred carrier）把信息带进 backend，最终落到 ELF section：

```text
IR plugin → IR metadata → SelectionDAG / MachineInstr PCSections → AsmPrinter → ELF
```

backend 自行生成的 RVV spill/reload 直接在 `MachineInstr` 上附加 PCSections。最终 transport 只有 PCSections。

- StackObject 输出 `.chimera.stackobj_map`（`[u64 LinkedVA][u32 SOID]`，每条 12 bytes，RV64；记录粒度=每条 MachineInstr 一条，由 LLVM patch 0008 保证——SelectionDAG 展开与 LTO 克隆均不得分组）。
- FunctionPointer 输出 `.chimera.function_pointer`（`[u64 call VA][u32 count][u64 target VA…]`）。

## 构建

仅构建 StackObject：

```bash
cmake -S chimera/preprocessing/offline/toolchain/llvm-21.1.0/plugins -B build/chimera-stackobject \
  -DLLVM_DIR=/path/to/llvm-21.1.0/lib/cmake/llvm \
  -DCHIMERA_ENABLE_STACKOBJECT=ON
cmake --build build/chimera-stackobject --target ChimeraStackObject
```

仅构建 SVF plugin：

```bash
cmake -S chimera/preprocessing/offline/toolchain/llvm-21.1.0/plugins -B build/chimera-svf \
  -DLLVM_DIR=/path/to/llvm-21.1.0/lib/cmake/llvm \
  -DSVF_DIR=/path/to/svf/lib/cmake/SVF \
  -DCHIMERA_ENABLE_SVF=ON
cmake --build build/chimera-svf --target ChimeraFunctionPointer
```

同时启用多个需要它的插件时仍只构建一份 `ChimeraCommon`。`ChimeraCommon` 不单独安装；启用插件会安装到 `${CMAKE_INSTALL_LIBDIR}/chimera/llvm/`，`extapi.bc` 随 SVF 插件安装。

## LLVM patch

`../../patches/` 仅针对干净的 `llvmorg-21.1.0`，按文件名前缀顺序 `git am`，不得跳号或并行应用。补丁清单以目录中的 `*.patch` 为准，涵盖 PCSections、RVV spill、safepoint、vectorizer gate 和 census。详见 [llvm-patches.md](llvm-patches.md)。

## 推荐阅读顺序

1. [architecture.md](architecture.md) —— 最终架构、模块边界、PCSections transport、三条 pipeline、wire format、classifier、inline-asm 规则、废弃方案。
2. [llvm-patches.md](llvm-patches.md) —— `patches/*.patch` 中的 patch 逐个说明。
3. [testing.md](testing.md) —— 可复现的测试指南；结果以 runner 输出为准。
