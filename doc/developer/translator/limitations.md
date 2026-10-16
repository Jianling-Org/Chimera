# 翻译器当前限制

本页说明当前翻译器的支持范围与已知限制。结构检查和局部执行回归不能替代完整目标机验证。

## 间接控制流

程序模式的 `jr`、`jalr x0` 和 `ret` 在查表返回原有效目标时恢复现场并执行原指令；返回不同地址时恢复后执行 `ebreak` 拒绝。需要改址的 AUIPC/JALR PLT/IFUNC 尾跳转也受此限制。查询返回零仍走诊断和终止路径。不能将当前实现描述为任意间接目标均可重定向。

## Fault-only-first load

正向 `vle8ff.v` 使用最多 32 字节的分块实现。源 VL=64、仅前 32 字节可读时，第二块的目标首元素 fault 仍可能产生异常，而不是源指令要求的缩短 VL。此缺陷尚未修复，对应执行回归保留严格 xfail；不应将预期失败计入已支持语义。

## 状态与实验后端

并非全部指令支持非零 `vstart` 重启。声明 `REQUIRE_ZERO` 的数据指令会拒绝非零值；CSR/config 恢复与支持架构重启的指令分别处理。内部 trap 不代表 Runtime 可以自动回到源程序恢复。

RVV256 → RVV1024 仍是实验性过渡后端，其 32 字节紧凑源寄存器布局不能与正向 128 字节状态槽混用。IME 输入仅限预展开符号汇编，不参与迁移查表与 offset map。

## 链接与验证

新生成汇编必须重新编译、链接并生成 offset map；旧 DSO 和地址表不能沿用。[共享对象链接](../architecture/translator.md#共享对象链接)介绍符号绑定与目标机验证要求。Python 回归和局部 QEMU 差分不替代 Linux/RISC-V 动态加载、多线程与完整迁移验收。

相关回归位于 `tests/test_control_flow_review_fixes.py`、`test_memory_review_regressions.py`、`test_review_forward_csr.py`、`test_review_reverse_state.py`、`test_translated_symbol_binding.py`（相对于翻译器目录）。
