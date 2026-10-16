# 翻译器测试与验证

以下命令从 `preprocessing/translator/rvv_sbt_tool/` 运行。Python 需要 3.11 及以上，pytest 需单独安装。

## 本地回归

```sh
PYTHONPATH=.:src python3 -m pytest tests -q -ra
python3 tools/generate_support_docs.py --check
python3 tools/check_backend_quality.py
```

仓库根目录的 `make translator-test` 汇总以上检查。`tests/` 覆盖解析、CFG/vtype、输出契约、状态保护和部分汇编、链接及 QEMU 执行；应分别报告 pass、skip 和 xfail。`tests/fixtures/objdump/` 包含 OpenBLAS、libc 和 vadd 的回归片段。

仅生成汇编不能证明可链接；链接成功不能证明执行正确；局部差分通过也不能替代完整迁移验收。完整状态差分应同时比较向量与 CSR 状态、可观察的 GPR/FPR、内存和 canary，并记录工具链、VLEN 与输入条件。

## 执行验证入口

| 入口 | 范围与环境 |
|---|---|
| `run_verify.py` | 标量 case 的翻译、构建和运行驱动；状态链接条件见下文 |
| [rvv256_wide](rvv256_wide/README.md) | RVV256 宽路径；RISC-V Linux 工具链与匹配的 QEMU/硬件 |
| [rvv1024_transition](rvv1024_transition/README.md) | 源紧凑状态 vlenb=32、目标硬件 vlenb=128 的过渡路径 |
| [ime_rvv](ime_rvv/README.md) | IME 展开差分；裸机工具链与 qemu-system-riscv64，或配套 A100 环境 |
| [rvv_bidirectional_hotspots](rvv_bidirectional_hotspots/README.md) | 双向点积热点与全状态差分；prepare 需要 Git checkout |
| [rvv_q3_gemm](rvv_q3_gemm/README.md) | 双向 RVV Q3_K GEMM，要求匹配的外部参考输入 |
| [ime_q3_gemm](ime_q3_gemm/README.md) | IME/RVV GEMM 对比，要求外部源码、参考输入与板端工具链 |

各目录的 README 给出实际参数和输入要求。Linux runner 与裸机 runner 的工具链不能混用。共享对象回归部分依赖 `ld.lld` 和 Linux ELF 动态加载器；板级 benchmark 还可能使用 OpenMP、taskset、timeout、sha256sum 与 perf。

## 标量驱动

```sh
python3 verify/run_verify.py list
python3 verify/run_verify.py check-env
python3 verify/run_verify.py translate --case daxpy_k
```

`check-env` 检查 Python、交叉编译器与 QEMU 是否可用，不验证状态符号是否可链接。当前标量 CLI 默认访问外部 TLS 状态，而该驱动的默认构建仅链接 `main.c` 和生成汇编，未提供状态实现。因此不能把默认 `full` 流程描述为自包含、可直接运行的验证；执行前需满足[状态 ABI](../../../../doc/developer/abi/translator-state.md)，并单独验证链接条件。

驱动仍提供 `build`、`run`、`full`、`clean` 和 `print-server-steps`，具体参数见 `--help`。不要依赖已不存在的 `.comm simulated_cpu_state` 自动定义。

## 验证边界

参考实现与翻译结果应使用相同输入，出现 unsupported、非法 vtype、越界或 canary 损坏时明确失败。mask、tail、vstart、FOF、规约和宽化/窄化需要覆盖相应状态与内存效果。已知拒绝与缺陷见[当前限制](../../../../doc/developer/translator/limitations.md)。

本目录保留验证源码和固定输入，不携带历史测量结果。性能只在通过正确性门禁后测量，并报告 CPU 绑定、频率、VLEN 和采样方法；QEMU 计时不能代替真实硬件性能。
