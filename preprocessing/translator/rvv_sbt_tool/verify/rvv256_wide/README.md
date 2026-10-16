# RVV256 宽路径目标语义验证

该目录验证 `rvv_sbt_rvv.py` 默认宽 LMUL profile 生成的真实 RVV 指令。它与
`verify/run_verify.py` 的标量后端验证相互独立，不能用其中一方的结果代替
另一方。

本文档同时记录 RVV256 宽路径的生成、目标机语义、迁移和性能门禁。不要把汇编成功或 pytest 通过表述成机器语义、迁移或性能已经验证。

```bash
cd rvv_sbt_tool

python3 verify/rvv256_wide/run_verify.py list
python3 verify/rvv256_wide/run_verify.py check-env
python3 verify/rvv256_wide/run_verify.py translate --case all
python3 verify/rvv256_wide/run_verify.py assemble --case all
python3 verify/rvv256_wide/report_codegen.py --with-object-size

# 真实 llama-perplexity 全程序检查（本地只做翻译和目标汇编）：
python3 verify/rvv256_wide/report_codegen.py \
  --program-input /path/to/program.s \
  --lib-name llama_perplexity \
  --with-object-size

# 在具有 RISC-V GCC 和支持 VLEN=256 RVV 1.0 的 QEMU/目标机上：
python3 verify/rvv256_wide/run_verify.py full --case all

# 在真实 RVV256 目标核构建并原生比较 legacy/wide；不要用 QEMU 周期作结论：
python3 verify/rvv256_wide/run_verify.py bench-build --case all --iterations 100000
python3 verify/rvv256_wide/run_verify.py bench-run --case all
```

每个 case 在忽略的 `artifacts/<case>/` 中生成：

- `translated.s`：可读宽路径汇编；
- `main.c`：独立 C reference（参考实现）和完整状态块比较；
- `verify.elf`：目标可执行文件；
- `translated.o` 与 `translated.objdump`：目标对象及反汇编证据。

测试把整个 `0x1040` 状态块初始化为 canary（哨兵值），并在状态块前后再放置
64B 越界 canary；普通用例明确以源 `vstart=0` 为前提，只修改期望的活动元素，随后逐字节比较。
`tests/test_vstart_contract.py` 单独验证非零 `vstart` 的拒绝路径在 guest 访存和模拟状态写入前停止，
并验证 CSR/config 能恢复 `vstart=0`；`tests/test_rvv256_vstart.py` 则独立验证声明为
`ARCHITECTURAL` 的 `vmacc.vx` 从真实 `vstart` 开始计算、保留此前元素并在成功后清零。
拒绝路径不代表支持非零 `vstart` 重启。当前 case 清单及 masked 子集以 `run_verify.py list` 的输出为准，覆盖 one-shot、m8 多块、向量尾部、整数/浮点、
unit/strided/segment memory、whole-register、widening reduction，以及原生
mask compare/logic/scan。性能结论必须在真实目标核另行测量；QEMU 只作为
语义门禁。

完整 llama 汇编默认使用与部署脚本一致的扩展 profile，其中包含
`Zvfh/Zvfhmin`；`vfwmul.vf e16` 的目标构建还要求 RISC-V GCC 接受
`-march=rv64gcv_zfh_zvfh`。工具链不支持时应明确失败，不能改用近似语义。

`report_codegen.py` 中的 `vset/vector_load/vector_store` 是静态文本计数。
宽路径为完整块和尾部分别保留一份正文，静态数量可能增加；动态执行次数应
按运行时 `vl` 和目标 LMUL 统计，并最终以固定 RVV256 核上的 cycle/perf
数据为准。

微型 fixture 和 `--program-input` 不能互相替代：fixture 提供含 RVV opcode 的
定向覆盖；完整共享库输入负责暴露函数级解析、控制流、地址映射、规模和目标汇编
问题。报告会显式输出 `vector_instruction_count`，若为 0，则该文件不能作为宽
LMUL/masked 语义或性能证据。

真机操作需要 RISC-V 目标环境。其中的 `stress-ng` 和 `/proc/set_ai_thread`
操作不得在 macOS 开发机上尝试；本地结果最高只到 LLVM 目标汇编门禁。

## 目标机语义门禁

要求 RISC-V GCC、objdump，以及支持 RVV 1.0/VLEN=256 的 QEMU 或真实机器：

```bash
python3 verify/rvv256_wide/run_verify.py check-env
python3 verify/rvv256_wide/run_verify.py full --case all
```

通过标准是所有 case 的整个 `0x1040` 状态块和受保护内存逐字节一致。当前开发机如果缺少 `riscv64-unknown-linux-gnu-gcc`、对应 objdump 或 `qemu-riscv64`，只能报告翻译和目标汇编结果，不能报告 L4 语义通过。

## 迁移门禁

必须在具备 Chimera 内核迁移接口的双向部署环境执行：

1. 用同一 fixture 分别生成 `--conservative` 和默认宽 profile 翻译库；
2. 将迁移触发点依次放在每个源 `branch_j_target_<addr>`；
3. 每次迁移前后保存线程 TLS 中完整的 `0x1040` 状态块；
4. 比较 legacy、wide 与源端参考的 vreg、`vl`、`vtype`、`vstart`；
5. 对目标物理 `v8-v31` 写入哨兵值，确认迁回后不依赖这些临时值；
6. 至少两个线程交错迁移，确认 `simulated_cpu_state_riscv64_rvv_1024_riscv64_rvv_256` 地址和值互不串扰。

若临时物理寄存器哨兵检查失败，不得部署宽路径，也不得用旧的 `v24-v31` 临时寄存器池实验推导 `v8-v31` 全池安全。macOS 开发机没有对应内核环境时，不得运行写 `/proc` 的迁移脚本。

## 性能门禁

只在固定 RVV256 真实目标核上原生执行：

```bash
python3 verify/rvv256_wide/run_verify.py bench-build --case all --iterations 100000
python3 verify/rvv256_wide/run_verify.py bench-run --case all
```

固定 CPU affinity（处理器亲和性）和频率，至少预热 5 轮、正式采样 30 轮，取中位数。性能结论必须来自真实目标核的 cycle/perf 数据；QEMU 周期数据和静态汇编大小不能作为性能证据。

## mask 与状态验证边界

宽路径的 masked case 必须比较完整状态块、前后 64B canary（哨兵区）和相关内存。bit-packed `v0`、`mu` 未命中元素、`vl` 之外的 mask bit，以及尾部元素都必须纳入差分。

`report_codegen.py` 输出的 `vset`、`vector_load`、`vector_store` 是静态文本计数。宽路径为完整块和尾部分别保留正文，静态数量可能增加；动态执行次数应按运行时 `vl` 和目标 LMUL 统计，不能从静态行数推导性能。

The legacy `default_*` case IDs remain accepted by `--case` because existing
consumers use them; `list` displays their `conservative_*` names and the exact
stable ID. Profile checks distinguish wide arithmetic from shared native mask
and whole-register paths. LLVM assembly tools default to PATH names and can be
selected explicitly with `--llvm-mc` and `--llvm-objdump`.

`report_codegen.py` counts `wide_blocks` using the exact `RVV256-WIDE:` marker,
separately from masked, commit and reduction markers. Vector-store counts exclude
shift and slide arithmetic. Historical metric JSON files are unchanged.
