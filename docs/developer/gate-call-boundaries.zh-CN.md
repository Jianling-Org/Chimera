# Gate 调用边界与原生标量调用闭包

在 RVV 异构迁移场景中，当函数包含手写或隐式 RVV 状态（如可伸缩向量寄存器、VLEN 栈对象、`vl`/`vtype` 状态）时，若该函数被直接内联到含有未解析间接调用或潜在外部回调的控制函数中，会导致控制流跨越敏感的向量生命周期。这在离线安全点检查中会被判定为 unsafe 并产生 finding，从而阻止该线程在运行时的自动迁移。

早期尝试直接在这些函数上添加全局 `noinline`、关闭 FlashAttention 瓦片路径（tiled path）或强制添加 Q8_K volatile 清零补丁。虽然能通过安全检查，但会严重打断纯计算路径（例如 llama.cpp 中 Q3_K 矩阵乘内层解包函数）的内联展开与寄存器分配，导致性能断崖式下降。

为此，Chimera 引入了**路径感知的 Gate 调用边界隔离**与**原生标量调用闭包证明（Native Call Closure）**机制：
- **编译插件层**：在控制流与潜在回调路径精准施加调用边界隔离，同时在纯计算路径保留满速内联；展开 gated 函数内的局部 memset intrinsic，避免后端降级为外部调用；
- **离线分析与准入层**：基于 ELF 实际机器码字节对外部标量数学函数提供无回调闭包证明，并严格绑定模块 SHA 与输入指纹，确保准入与运行时环境的一致性。

---

## 1. 编译插件机制

编译阶段由 LLVM 插件中的 `GateRvvBoundaryPass` 与 `GateLocalMemsetPass` 协作完成，旨在消除不必要的跨边界向量状态逃逸。

### 1.1 `GateRvvBoundaryPass`：路径感知的精准边界隔离

`GateRvvBoundaryPass` 运行在 LLVM 模块级内联阶段之前：

1. **Gate 属性传播**：
   - 遍历由 Gate 根可达的直接调用图；
   - 检查被调函数是否具有显式 RVV 状态（包括 Scalable Vector 类型参数/返回值/指令/Alloca，以及向量寄存器 clobber `~{v[0-9]+}`）；
   - 对包含显式 RVV 状态的函数统一定义级添加 `chimera-no-vectorize` 属性，防止优化器在 Gate 上下文中对这些辅助函数重新进行隐式自动向量化。

2. **区分计算路径与回调控制路径的精准内联控制**：
   - **反向定位回调上下文**：从包含未解析间接调用的函数开始，沿调用图反向标记所有可到达该间接调用的调用者（构成 `BoundaryContext`）；
   - **标量接口调用点隔离**：在 `BoundaryContext` 内，沿标量包装函数自顶向下查找首次引入显式 RVV 状态的调用。如果该调用点使用纯标量接口（参数与返回值均不携带可伸缩向量类型），则仅在**该特定 CallSite** 上添加 `noinline` 并移除 `alwaysinline`；
   - **允许包装函数本身内联**：外层的标量包装函数仍然允许内联并把受保护的调用点带入外层控制函数中；
   - **纯计算路径完全放行**：如果同一个 RVV 函数被纯计算密集型路径调用（该路径不会流向未解析的间接调用/外部回调），则调用点不添加 `noinline`，允许编译器完全内联优化；
   - **保留符号语义**：保留函数原有身份、链接属性与源码内联标记，不克隆或替换函数实体。

> **典型案例（llama.cpp）**：
> - **Q3_K 算子解包**：内层两个解包函数在纯计算密集路径中完整内联，避免了每次循环迭代都反复保存和恢复 32 个向量寄存器；
> - **`out_prod` 量化回调**：在带有量化回调函数指针的控制路径上精准保持调用边界，使 VLEN 栈帧与向量寄存器隔离在叶子函数内，彻底解决逃逸问题。

### 1.2 `GateLocalMemsetPass`：消除隐式外部 memset 调用

当函数使用 Gate 属性时，若函数内部存在 `llvm.memset.*` intrinsic，LLVM 代码生成后端有可能在寄存器分配或 Lowering 阶段将其降级为对系统 libc `memset` 的外部调用。这会在跨外部调用边界时留下显式 RVV 活跃状态。

- `GateLocalMemsetPass` 在最后一个 IR 优化阶段拦截 gated 函数中的 `llvm.memset.*`；
- 将其展开为局部标量字节循环（Byte-by-byte loop）；
- 完整保留 `volatile` 标记、Debug Location 以及适用的别名（Alias）元数据；
- 展开循环保证 0 长度时不访问目标地址，且 32 位长度在 64 位地址空间下执行安全的无符号扩展；
- 未被 gated 的普通函数和源码中显式编写的外部 `memset(...)` 调用保持原样不变。

---

## 2. 原生标量调用闭包证明（Native Call Closure）

在离线静态分析阶段，若应用程序的向量宽度值或条件控制流跨越了外部原生函数调用（例如 `sin`、`cos` 等标准数学库函数），外部调用将被判定为潜在开放边界（可能存在重入回调）。

新增的原生调用闭包证明通过严格的形式化静态证明，证明目标外部原生函数**绝不可能回调应用程序代码**。

### 2.1 证明与边界准入规则

闭包证明直接分析实际选定的 **RV64 LP64D ELF 实际二进制字节**，绝不根据库名（如 libm.so）或符号名称进行特权豁免：

* **动态符号与绑定核验**：
  - 验证符号在动态符号表中唯一、版本匹配；
  - 验证标准 PLT 机器码、GOT 条目和 `R_RISCV_JUMP_SLOT` 重定位严格一致。
* **内存访问约束**：
  - 仅允许写入当前调用的私有栈帧（Private Stack Frame）以及已重绑定的本线程 TLS 对象；
  - 不可变数据（Rodata / 经过验证的相等加载）仅允许用于分支证明；加载器初始化的 RELRO 数据不被当作 ELF 初始常量。
* **寄存器与控制流约束**：
  - 精确检查函数范围、所有可达直接调用与尾调用；
  - 验证所有 ABI Callee-saved 寄存器（`s0-s11`, `fs0-fs11`）和栈指针 `sp`、返回地址 `ra` 均被合规保存和恢复。

### 2.2 绝对拒绝证明的情形

一旦在遍历目标外部函数机器码时发现以下任意情形，立即终止证明并保留开放边界（继续报 `active-external-call` finding）：
- 包含间接调用（`jalr` 目标不可解）或可能回调应用的路径；
- 存在 GNU IFUNC 间接函数解析；
- 存在符号劫持或多重冲突定义；
- 出现向量指令、CSR 指令或系统特权指令（`ecall` / `ebreak`）；
- 出现不可分析的内存写操作或未知指令字节；
- 存在直接/间接递归，或函数规模超出预算限额。

### 2.3 证明规模与资源预算限额

为了防止离线静态分析陷入路径爆炸或遭遇对抗性二进制构造，证明引擎设定了严格的硬性预算限额：

| 约束项 | 限额指标 | 超限行为 |
|---|---|---|
| **单根最大遍历函数数** | $\le 64$ 个函数 | 抛出 `ClosureRefusal`，放弃闭包并保持开放边界 |
| **单根最大累计代码量** | $\le 128 \text{ KiB}$ | 同上 |
| **单个函数代码尺寸上限** | $\le 4096 \text{ Bytes}$ | 同上 |
| **数据流分析步数上限** | 有界步数与时间超时 | 同上 |

---

## 3. 工件凭证与运行时安全绑定

证明结果不能作为永久豁免，必须严格随环境指纹绑定：

1. **工件保存**：
   - 证明结果以 `chimera-external-call-contracts-v3` 格式保存在 Workspace 中；
   - 检查凭证版本升级为 **v34**。
2. **输入指纹绑定（`check_input_fingerprint`）**：
   - 凭证与实际选定的模块集合、绝对/相对路径、文件 SHA-256、标量库选型和交付方式强绑定；
   - 任何依赖库的升级、替换或路径变更都会使现有指纹失效，强制要求重新执行 `check-elf`；
   - 即使传入 `--allow-problematic` 参数也无法绕过输入指纹校验。
3. **工作区准备阶段（Prepare）**：
   - `prepare` 阶段会对本次实际选定的模块重新进行依赖闭包分析，绝不盲目跨实例复用缓存；
   - 若某边界未能重新获得有效证明，该调用边界自动回退为开放状态并恢复原有 unsafe finding。
4. **运行时动态加载防御（Runtime Protection）**：
   - 运行时启动器校验所有加载 ELF 的代码段 SHA、根导入、对象与 TLS 重定位；
   - 严格拦截符号抢占，禁止任何形式的 `LD_PRELOAD`、`LD_AUDIT`、`LD_PROFILE` 或系统级 preload 注入。

---

## 4. 验证测试与回归指引

本次机制在 LLVM 插件、离线分析器以及运行时均配备了完备的自动化测试：

### 4.1 LLVM 插件与 IR 变换回归测试
* **测试文件**：
  - `preprocessing/offline/toolchain/llvm-21.1.0/plugins/tests/vector_gate/test_rvv_boundaries.py`
  - `preprocessing/offline/toolchain/llvm-21.1.0/plugins/tests/vector_gate/call-boundaries.ll`
  - `preprocessing/offline/toolchain/llvm-21.1.0/plugins/tests/vector_gate/test_live_memset.py`
  - `preprocessing/offline/toolchain/llvm-21.1.0/plugins/tests/vector_gate/test_live_rvv_boundary.py`
* **覆盖内容**：
  - 纯计算路径 vs 间接回调路径的差异化内联决策；
  - 标量包装函数内联与 CallSite 级别的 `noinline` 属性保留；
  - `memset` intrinsic 转换为展开字节循环（覆盖 volatile、0 长度保护和 32 位扩展）。

### 4.2 离线原生闭包算法单元测试
* **测试文件**：
  - `tests/test_native_call_closure.py`
  - `tests/test_binary_checks.py`
* **执行命令**：
  ```bash
  pytest tests/test_native_call_closure.py tests/test_binary_checks.py
  ```
* **覆盖内容**：
  - 真实 RISC-V ELF 的 PLT 机器码解析、符号版本匹配；
  - 各种边界破坏场景（非标准栈操作、Callee-saved 寄存器破坏、系统指令、IFUNC 劫持）的精准拒绝；
  - 64 函数与 128 KiB 预算截断测试。

### 4.3 验收判定标准
1. **静态准入标准**：应用二进制经过 `check-elf --strict`，findings 必须为 0，且 `passed=true`；
2. **端到端迁移判据**：
   - 编译器和离线测试通过不等于完整模型迁移通过；
   - 候选工具链、无侵入性补丁构建的应用、原生参考与真实自动迁移结果须分别独立记录；
   - 数值精度判据遵循已明确授权的 **PPL 相对误差 $\le 2\%$** 规则。

