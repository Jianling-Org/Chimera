# `simulated_cpu_state` 状态 ABI

`simulated_cpu_state` 是翻译器、运行时、地址映射和迁移逻辑之间的跨层应用二进制接口（ABI）。它不是某个后端的私有临时缓冲区。修改字段位置、每个向量槽大小或状态基址获取方式，必须同时检查 `rvv_sbt_tool`、`runtime/runtime/state/linux_riscv64_rvv_v1/translator_state.c`、偏移表和目标机测试。

## 固定布局

当前布局的权威是 `src/riscv/extensions/rvv/runtime/layout.py` 的 `SimulatedStateLayout`
（常量 `VREG_SIZE=128`、`STATE_TOTAL_SIZE=0x1040`、`CSR_OFFSETS`）；
调用方直接消费 `SimulatedStateLayout`，不再经过 `RegAllocator` 包装。
逻辑总大小为 `0x1040`（4160）字节：

| 偏移 | 大小 | 内容 | 说明 |
|---:|---:|---|---|
| `0x000`–`0xF80` | 32 × 128 B | `v0`–`v31` | 每个模拟向量寄存器固定 128 B，表示 VLEN=1024 的语义槽 |
| `0x1000` | 8 B | `vstart` | 向量指令起始元素 |
| `0x1008` | 8 B | `vxsat` | 饱和标志 |
| `0x1010` | 8 B | `vxrm` | 舍入模式 |
| `0x1018` | 8 B | `vcsr` | 向量控制状态寄存器 |
| `0x1020` | 8 B | `vl` | 当前活动向量长度 |
| `0x1028` | 8 B | `vtype` | 当前向量类型编码 |
| `0x1030` | 8 B | `vlenb` | 客体可见的每个向量寄存器字节数 |
| `0x1038`–`0x103F` | 8 B | 保留 | 不得作为新语义字段使用，除非同步修改 ABI 所有者 |

双向 RVV 后端以 `vcsr` 的低 3 位作为 `vxrm/vxsat` 的权威值：
`vxrm = (vcsr >> 1) & 3`，`vxsat = vcsr & 1`。正向 CSR 写/RMW 与
`vnclip` 更新该值时同步两个历史独立槽位；读取字段时仍从 `vcsr` 解码，
不能假设 Runtime 已初始化独立槽位。反向继续使用原有的 `vcsr` 权威约定。

配置指令完成后清零模拟 `vstart`，CSR 读写则保留其架构副作用。三个后端
的非零 `vstart` 拒绝仅用于声明 `REQUIRE_ZERO` 的数据指令，不能阻止 CSR
清零或配置恢复。正向和标量指令的 `sp` 结果在保护帧恢复后才提交，避免
内部恢复操作使用客体的新栈指针。

正向与标量通过共享 `translation/vector_csr.py` 模拟 13 种 CSR form，
按 `context.layout.vlenb` 确定源 VLENB 和 `vstart` 可写位。
`REQUIRE_ZERO` 拒绝发生在数据执行之前，但保护帧仍在；Runtime 对未映射
内部 trap 终止执行，不能把这个拒绝路径当作自动回到源程序的恢复入口。

`SimulatedStateLayout.get_total_size()` 的逻辑布局是 `0x1040`。当前运行时在 `runtime/runtime/state/linux_riscv64_rvv_v1/translator_state.c` 为两个方向分别分配 4192 字节的 TLS 状态数组；这是运行时的容纳尺寸，不代表可以改变上表中的偏移。

## 三个后端如何解释它

每个后端的方向参数（源/目标 VLENB、比值、块元素数、整寄存器搬运宽度）
来自 `src/riscv/extensions/rvv/runtime/geometry.py` 的 `TranslationGeometry`；已登记方向仅
`128→32` 与 `32→128`，非法方向在 profile 构造期被拒绝：

| 后端 | 客体/源状态 | 目标执行环境 | 向量 payload 解释 |
|---|---|---|---|
| 标量 | VLEN=1024，`vlenb=128` | 标量 RV64 | 逐元素从固定 128B 槽加载/写回 |
| RVV256 | VLEN=1024，状态槽仍是 128B；`--vlenb` 只接受 128 | 目标 VLEN=256，`vlenb=32` | 每条源指令按 `ratio=4` 分块处理，结果写回 128B 槽 |
| RVV1024 过渡实验 | 源状态是 RVV256 紧凑布局，`source_vlenb=32` | 目标 VLEN=1024，`target_vlenb=128` | 经 `state_view` 按 `state + N * 32` 解释；不能把紧凑源布局当作旧 128B 槽布局 |

这里的 `vlenb` 参数有两个层次：`StateTracker`/handler 使用的是客体源语义；目标机 CSR `vlenb` 是硬件能力。过渡后端显式把两者分开，并在入口做 `32 → 128` profile guard；RVV256 入口则在构造 profile 时经方向白名单校验 `--vlenb == 128`。

## 状态基址与寄存器约束

默认 `ProgramEmitter` 组合的 `StateAccessEmitter` 在每个翻译块内部通过 Initial-Exec TLS 获取状态地址：

```asm
la.tls.ie t6, simulated_cpu_state_ptr
add       t6, t6, tp
```

`StateAccessEmitter` 同时是内部合同标记 `STATE_BASE_MARKER`
（`CHIMERA_STATE_BASE`）的唯一所有者：状态地址发射者（RVV256 的
`chunk.py`、过渡路径的 `state_view.py`）把它写进汇编注释，
`VectorBlockEmitter` 据此区分“语义 t6 改写”与“必须指向状态块的 t6”。
该字符串只在 core 定义一次，后端引用常量。

约束如下：

- `t6` 只在当前翻译块内是状态基址，不得假设它跨原始指令、函数调用或 `branch_j_target_*` 入口永久有效；
- wrapper 必须按实际 handler 触及的 caller-saved 寄存器保存/恢复，不能把 `t6` 当成永远空闲的临时寄存器；
- `--state-base-mode helper` 是动态加载或 TLS 门禁不满足时的兼容回退；
- Initial-Exec TLS 要求 Runtime 预加载库 在进程启动期通过 `LD_PRELOAD` 加载。翻译库由 `dlopen` 装入这一部署组合仍需在 RISC-V 目标机验证；
- `simulated_cpu_state_ptr` 是运行时导出的 TLS 对象，不能只修改翻译器文本而不检查 `runtime/runtime/state/linux_riscv64_rvv_v1/translator_state.c`。

## 写回和迁移安全点

当前每个 `branch_j_target_<address>` 都可能作为迁移入口。因此默认合同是：

1. 翻译块开始前从状态 ABI 读取需要的 vreg/CSR；
2. 完成当前源 RVV 指令；
3. 在离开该源指令前把结果和 CSR 写回状态 ABI；
4. 控制流重写、函数返回或迁移入口都以已写回的状态块为权威。

在没有新增安全区域、dirty 状态表、flush 出口和 offset-map 合同之前，不得跨源指令缓存 dirty 向量寄存器，也不得因为局部性能优化省略写回。

## 现有 Runtime 接口下的支持边界

翻译器使用现有状态布局、地址查询接口和 offset-map 格式，不依赖额外的
mapped-jump 或软件 FOF Runtime 协作入口，也不提供相应的异常恢复协议。

程序模式的 `jr`、`jalr x0`、`ret` 保存源有效目标并调用既有查询接口。
identity 结果恢复现场后执行原跳转；非 identity 结果恢复全部 GPR、调用者
FPR、fcsr 和 SP 后 `ebreak` 拒绝。目标地址不能写回本来只读的源寄存器，
包括 `ret` 的 `ra`。查询返回零仍沿既有内部 trap 诊断路径终止。

正向 `vle8ff.v` 专用 handler 使用最多 32 字节的分块实现，没有额外的
256 元素容量上限。每个 chunk 完成后累加实际加载数量，块内非首元素 fault
导致的缩 VL 会写回模拟状态。后续 chunk 的首元素 fault 仍可能错误触发异常，
该缺陷尚未修复。非零源 `vstart` guard 和输入校验仍然执行；该路径不支持
非零重启，也没有 Runtime 异常恢复协议。

当前支持边界见[已知限制](../translator/limitations.md)。若旧译后产物引用了当前 Runtime 不再提供的协作入口，必须重新生成或停用。

## 修改 ABI 前的检查清单

- `src/riscv/extensions/rvv/runtime/layout.py` 的向量和 CSR offset 常量；
- `src/riscv/extensions/rvv/runtime/geometry.py` 的方向登记（新方向需同步 `TranslationGeometry` 校验、profile 白名单和 `tests/test_geometry.py`）；
- `src/riscv/extensions/rvv/analysis/model.py` 的 LMUL 指令集事实表（`LEGAL_LMULS`/`LMUL_TOKENS`）；
- `src/riscv/extensions/rvv/translation/vtype_decode.py` 的运行时 vtype→VLMAX 解码（两后端共享）；
- `src/riscv/extensions/rvv/runtime/access.py` 的 `STATE_BASE_MARKER` 与状态基址装载；
- `runtime/runtime/state/linux_riscv64_rvv_v1/translator_state.c` 的线程状态大小、TLS 符号和导出函数；
- `StateAccessEmitter`、`VectorBlockEmitter` 的状态基址和保存寄存器集合；
- `src/riscv/extensions/rvv/backends/rvv256` 的 chunk/state 访问和 RVV1024 `state_view`；
- offset map、迁移入口和 `branch_j_target_*`；
- 标量、RVV256、RVV1024 三套验证中的完整 state/memory 差分；
- 目标 RISC-V 汇编、链接、动态加载和多线程 TLS 实验。

本文件只描述当前 ABI，不表示 Initial-Exec TLS、迁移路径或目标硬件已经在所有部署环境中验证完成。
