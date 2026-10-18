# `tests/` 说明

`tests/` 负责做**结构化测试**，目标是尽快发现解析、状态追踪、分发和代码生成层面的回归。

目标机上的运行与数值验证见 [`../verify/README.md`](../verify/README.md)。

## 注意事项

- Linux / macOS 通常使用 `python3`
- Windows 通常使用 `python`
- 下文示例统一写成 `python3 ...`；如果你在 Windows 上执行，请将其替换为 `python ...`

## 如何运行

pytest 模块不提供 `__main__` 手工驱动（`test_architecture_boundaries.py`
静态禁止），直接执行 `python3 tests/test_backend.py` 会静默退出且不做任何
事。统一使用 pytest：

```bash
# 推荐：完整结构/流程回归
python3 -m pytest tests -q

# 单文件
python3 -m pytest tests/test_backend.py -q
python3 -m pytest tests/test_rvv_state.py -q
python3 -m pytest tests/test_integration.py -q

# 单个用例
python3 -m pytest tests/test_rvv256.py::TestClass::test_method -q
```

## fixture 布局

`tests/fixtures/` 现在按来源分层：

- `tests/fixtures/obj/`：原始 `.o`
- `tests/fixtures/objdump/`：`llvm-objdump -d` 生成的文本 fixture

命名约定：

- `*.o`：原始目标文件
- `*.objdump.s`：反汇编文本
- `*_translated.s`：翻译输出

## 生成 fixture

列出已登记的 fixture case：

```bash
python3 tests/generate_fixtures.py list
```

按 case 刷新 objdump fixture：

```bash
python3 tests/generate_fixtures.py generate --case saxpy_k
```

对任意 `.o` 做一次性生成：

```bash
python3 tests/generate_fixtures.py generate \
  --input tests/fixtures/obj/your_kernel.o \
  --output tests/fixtures/objdump/your_kernel.objdump.s
```

## 各测试文件的职责

除下列核心文件外，`test_rvv256*.py`、`test_rvv1024_*.py` 分别覆盖对应后端的
具体合同；`test_architecture_boundaries.py`
静态锁定模块依赖方向和已删除的旧命名空间不可恢复。

### `test_backend.py`

检查标量后端分发和单条 RVV 指令的翻译结果，重点包括：

- `ScalarDispatcher` 初始化与 registry 能力分类
- 已实现 RVV 指令能否被正确分发
- plan/lower 两阶段的校验失败统一收敛为 `UnsupportedInstructionError`
- 循环标签计数器是否正常工作

这类测试主要看“某条指令是否被翻译成了预期的标量模板”。

### `test_rvv_state.py`

检查中间层状态与布局，重点包括：

- 向量寄存器偏移分配是否正确（经 `SimulatedStateLayout`）
- `SEW` / `LMUL` / `VLMAX` 状态更新是否正确
- `vsetvli` / `vsetivli` 的状态追踪是否正确

这类测试不关心最终汇编能否运行，重点是内部状态是否一致。

### `test_geometry.py`

锁定翻译方向几何的单一权威：已登记方向白名单（`128→32`、`32→128`）、
非法方向 fail-fast、派生量（`ratio=4`、块元素数、整寄存器搬运宽度），
以及宽路径规划器使用几何比值而非内联常量。

### `test_vtype_decode.py`

锁定共享 vtype→VLMAX 解码发射器：RVV 1.0 完整合法性检查（vill、保留位、
保留 vlmul）都在场；两个后端的解码序列仅因源 VLENB 一行不同；两个
config handler 都引用同一共享实现。

### `test_integration.py`

检查从“解析输入”到“生成单函数输出”的完整流程。

当前它围绕多个固定样例：

- `tests/fixtures/objdump/vadd_rvv.objdump.s`
- `tests/fixtures/objdump/daxpy_k.objdump.s`
- `tests/fixtures/objdump/saxpy_k.objdump.s`
- `tests/fixtures/objdump/caxpy_k.objdump.s`
- `tests/fixtures/objdump/zaxpy_k.objdump.s`

它重点验证：

- `AsmParser` 能否正确解析输入
- `TranslationPipeline.prepare()` + `emit_function()` 能否生成完整函数
- 输出中是否保留关键标签、段信息和 `simulated_cpu_state`
- `translate()` 兼容入口是否仍然正确转到单函数路径

注意：这里的“集成”依然是**翻译流程集成**，不是运行期语义验证。

## 当前测试假设

这些测试现在默认遵循项目当前策略：

- 输入以**单函数 objdump 片段**为主
- 主路径是 `TranslationPipeline.prepare()` 后调用 `emit_function()`（程序模式为 `emit_program()`；JAL 范围探测复用同一 `PreparedTranslation` 多轮发射）

如果后续恢复多函数输入支持，`test_integration.py` 需要同步调整。

## fixtures

### `fixtures/objdump/`

输入样例：

- `daxpy_k.objdump.s`：OpenBLAS 的 `daxpy` 相关单函数片段
- `saxpy_k.objdump.s`：OpenBLAS 的 `saxpy` 相关单函数片段
- `caxpy_k.objdump.s`：OpenBLAS 的 `caxpy` 相关单函数片段
- `zaxpy_k.objdump.s`：OpenBLAS 的 `zaxpy` 相关单函数片段
- `vadd_rvv.objdump.s`：较小的 RVV 加法样例

重构前曾提交两份完整翻译输出用于人工对照；它们不参与自动断言，现已移出
仓库。需要整程序前后对比时应把两轮结果写入临时目录并执行规范化 ``diff``，
不能把大型或易过期的生成汇编重新提交到 ``tests/``。

## 如何补充新测试

新增指令时，建议按两层补：

1. 在对应后端的 `test_rvv256.py` / `test_rvv1024_*.py` 中补单条指令级测试
2. 在 `test_integration.py` 中补真实样例或最小片段

涉及翻译方向几何、LMUL 表或 vtype 解码的改动，必须同步
`test_geometry.py` / `test_vtype_decode.py` 并通过
`python3 tools/check_backend_quality.py`。

如果你要验证“翻译后的程序在 Linux + QEMU 上是否算对”，不要把这类逻辑塞进 `tests/`，而应放到 `verify/`。
