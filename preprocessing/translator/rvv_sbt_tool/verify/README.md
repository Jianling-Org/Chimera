# 翻译器语义验证说明

`verify/` 用来验证：**翻译后的标量汇编在运行时是否符合预期语义**。

这和 [`../tests/`](../tests) 的职责不同：

- `tests/`：检查翻译流程本身是否正常
- `verify/`：检查生成物是否能编译、运行，并给出正确结果

## 证据等级

翻译器的“能找到 handler”“能生成汇编”“目标机结果正确”和“性能提升”是不同结论。报告时必须区分以下证据层级：

| 等级 | 证据 | 能说明什么 | 不能说明什么 |
|---|---|---|---|
| L0 | dispatcher 注册、handler 单元测试或文本模板测试 | 代码路径存在，接口基本可调用 | operand、tail/mask、状态和机器语义正确 |
| L1 | `python3 -m pytest tests -q` | 解析、流程、fixture 合同和本地结构回归通过 | 目标 RISC-V 汇编器、链接、真实执行 |
| L2 | RISC-V assembler 接受并生成对象 | 汇编语法、部分寄存器和重定位约束满足 | 跨函数链接、运行时状态、算术语义 |
| L3 | 目标环境链接成功 | 符号、重定位和 ABI 在该链接命令下可用 | reference/candidate 结果等价、迁移安全 |
| L4 | QEMU 或真实 RISC-V 目标上的 reference/candidate 差分 | 在明确假设下验证状态、标量寄存器和内存语义 | 未覆盖的 vtype、异常、并发和所有 opcode |
| L5 | 真实目标机部署与性能实验 | 目标硬件上的运行合同、吞吐/延迟或迁移效果 | 对未测输入和其他硬件的普遍正确性 |

静态输出长度、pytest 通过、宿主机不崩溃和某个 OpenBLAS kernel 运行成功，都不能单独升级到 L4 或 L5。

## 各模式的验证入口

- 标量后端：本文档中的 `run_verify.py`，调用 `rvv_sbt.py`；
- RVV256 宽路径：[`verify/rvv256_wide/README.md`](rvv256_wide/README.md)，需要单独检查 VLEN=256、状态写回和 mask 形式；
- RVV1024 过渡实验：[`verify/rvv1024_transition/README.md`](rvv1024_transition/README.md)，需要源状态 `vlenb=32` 和目标硬件 `vlenb=128`。

标量验证结果不能替代 RVV256 或 RVV1024 的目标机验证。

## 当前目录组织

每个验证 case 独立放在一个子目录下，例如：

- `verify/vadd_rvv/`
- `verify/daxpy_k/`
- `verify/saxpy_k/`
- `verify/dcopy_k/`
- `verify/ccopy_k/`
- `verify/scopy_k/`
- `verify/dswap_k/`
- `verify/sswap_k/`
- `verify/caxpy_k/`
- `verify/zaxpy_k/`
- `verify/dscal_k/`
- `verify/sscal_k/`
- `verify/ddot_k/`
- `verify/sdot_k/`

每个 case 目前至少包含：

- `main.c`：验证 harness

运行后可能生成：

- `translated.s`：翻译器生成的标量汇编
- `verify.elf`：交叉编译后的可执行文件

统一入口是 `verify/run_verify.py`。

## 注意事项

- Linux / macOS 通常使用 `python3`
- Windows 通常使用 `python`
- 下文示例统一写成 `python3 ...`；如果你在 Windows 上执行，请将其替换为 `python ...`

## 当前推荐工作流

推荐按“翻译”和“构建/运行”分步执行：

### 第一阶段：本机只做翻译

```bash
python3 verify/run_verify.py translate --case daxpy_k
python3 verify/run_verify.py translate --case ccopy_k
python3 verify/run_verify.py translate --case ddot_k
```

其余 case 使用同样形式：

- `python3 verify/run_verify.py translate --case <case_name>`

### 第二阶段：在具备完整工具链的环境中构建并运行

```bash
python3 verify/run_verify.py build --case daxpy_k
python3 verify/run_verify.py run --case daxpy_k
```

如果当前环境缺少交叉编译器或 `qemu-riscv64`，可以先生成 `translated.s`，再到具备对应工具的环境继续。

## 环境检查

```bash
python3 verify/run_verify.py check-env
```

它会分别检查：

- 本地翻译所需工具：Linux / macOS 通常为 `python3`，Windows 通常为 `python`
- 构建/运行所需工具：`riscv64-unknown-linux-gnu-gcc`、`qemu-riscv64`

## 可用命令

### 列出 case

```bash
python3 verify/run_verify.py list
```

### 只翻译，不构建

```bash
python3 verify/run_verify.py translate --case daxpy_k
```

### 只构建

```bash
python3 verify/run_verify.py build --case daxpy_k
```

### 只运行

```bash
python3 verify/run_verify.py run --case daxpy_k
```

### 在同一台完整工具链机器上跑完整流程

```bash
python3 verify/run_verify.py full --case daxpy_k
```

### 清理产物

```bash
python3 verify/run_verify.py clean --case all
```

### 打印后续环境应执行的步骤

```bash
python3 verify/run_verify.py print-server-steps --case daxpy_k
```

## `run_verify.py` 的动作含义

- `list`：列出所有语义验证 case
- `check-env`：检查当前机器上有哪些工具可用
- `translate`：调用 `rvv_sbt.py` 生成 `translated.s`
- 如果遇到未支持的 RVV 指令，`translate` 会直接报错并退出，不再生成带 `TODO` 注释的“伪成功”输出
- `build`：用交叉编译器构建 `verify.elf`
- `run`：通过 `qemu-riscv64` 执行 `verify.elf`
- `full`：按 `translate -> build -> run` 串起来执行
- `clean`：删除 `translated.s` 和 `verify.elf`
- `print-server-steps`：输出后续构建/运行环境可直接执行的命令

## 语义差分的最低合同

对一个声称“语义已验证”的 case，reference（参考实现）和 candidate（翻译结果）必须：

1. 使用同一初始 `simulated_cpu_state`，包括 vreg、`vl`、`vtype`、`vstart`、`vcsr`；
2. 使用同一标量寄存器输入和同一内存/保护区；
3. 比较完整状态块，而不只比较返回值；
4. 比较指令可观察的标量寄存器和内存效果；
5. 对失败、越界、unsupported、非法 vtype 和 canary 损坏明确失败；
6. 记录目标工具链、QEMU/硬件 VLEN、编译参数和 case 假设。

对于 mask、tail、`vstart`、FOF、规约、widening/narrowing 和跨函数控制流，必须将对应状态字段和内存影响纳入差分，不能只做汇编文本检查。

## 验证报告模板

每次报告建议至少写清：

```text
代码路径/模式：标量 | RVV256 | RVV1024 过渡
测试用例：...
L0 handler/注册：通过 | 未通过
L1 pytest：通过 | 未通过（命令和数量）
L2 目标汇编：通过 | 未执行
L3 目标链接：通过 | 未执行
L4 状态/寄存器/内存差分：通过 | 未执行 | 失败
L5 真实目标机部署/性能：通过 | 未执行
限制与假设：...
```

## 约束与注意事项

- 当前验证对象是**翻译后的输出**
- 当前主翻译路径是 `translate_function()` / `TranslationPipeline.emit_function()`
- `main.c` 不需要再自行定义 `simulated_cpu_state`，由 `translated.s` 中的 `.comm simulated_cpu_state` 提供
- 这里更适合放“能否跑通、结果是否正确”的 case，不适合塞大量翻译细节断言

如果后续需要加入“原始 RVV 程序 vs 翻译后程序”的对比验证，建议单独扩展新流程，不要直接把两套逻辑混进现有脚本。
