# 双向 RVV 主 Q3_K GEMM 验证

主算子为真实提取的 `ggml_gemm_q3_K_64x1_q8_K`。三个点积函数保留在
`../rvv_bidirectional_hotspots`，用于局部消融与回归。分批优化以本目录的四形状
主 GEMM 收益为验收依据。

| 用途 | M×N×K | 每个 worker 的 nr/nc |
|---|---|---|
| FFN gate/up | 32×5632×2048 | 32/704 |
| FFN down | 32×2048×5632 | 32/256 |
| Attention Q/output | 32×2048×2048 | 32/256 |
| Attention K/V | 32×256×2048 | 16/64 |

沿用历史8线程静态列/行分块、Q3_Kx64/Q8_Kx4量化布局、seed、独立参考和
`bs=N+16`。正向模拟源 VLEN1024，目标为 CPU0–7/X100、VLEN256、2.2 GHz；
反向模拟源 VLEN256，目标为 CPU8–15/A100、VLEN1024、1.8 GHz。

历史实验输入身份见[验证记录](../../../../../docs/validation/measured-artifacts.json)。该输入的函数入口 `0x5ad99e`，1140条指令、356条RVV指令、3580B机器码。
当前提取与历史、IME比较中复用的原生 RVV kernel 机器码逐字节相同。
同一函数在源 VLEN1024/256 下分别走 VL64/VL16 分支，保持两种源语义。

两条路径均完整生成，unsupported/fallback为零。正向43个trap是VLMAX不变性guard；
反向另有356个profile/vstart guard。分支必须按源PC重新绑定局部标签，原函数offset
不能直接用作展开后的跳转位置。原有逐条1:N、立即提交、寄存器/CSR合同保持。

已接入主路径、累计收益、六批验收与基线口径见 [RESULTS.md](RESULTS.md)。计时包含原kernel
与LLVM OpenMP调度，packing、TLS初始化、环境门禁和校验在计时外。
使用CLOCK_MONOTONIC_RAW、3次预热、独立pilot校准约100ms批次、50个保留样本。
计时前后核对每worker的CPU、单核affinity、硬件vlenb、频率和未重置的TLS canary。

复现时先准备同指纹的四份历史独立参考，再生成当前翻译：

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 PYTHONPATH=.:src \
  python3 verify/rvv_q3_gemm/prepare.py --references /path/to/historical \
  --out /path/to/payload
```

在板端独立目录编译。`kernel.S`通过incbin保留原生机器码：

```sh
gcc -march=rv64gcv_zfh_zvfh_zba_zbb_zbs_zfa_zicond_zihintntl -mabi=lp64d -c kernel.S -o native-kernel.o
gcc -march=rv64gcv_zfh_zvfh_zba_zbb_zbs_zfa_zicond_zihintntl -mabi=lp64d -c forward.S -o forward-kernel.o
gcc -march=rv64gcv_zfh_zvfh_zba_zbb_zbs_zfa_zicond_zihintntl -mabi=lp64d -c reverse.S -o reverse-kernel.o
sh build.sh "$PWD/native-kernel.o" "$PWD/forward-kernel.o" "$PWD/reverse-kernel.o" 3
python3 run.py --implementations native256 native1024 forward reverse --phase pilot
sh build.sh "$PWD/native-kernel.o" "$PWD/forward-kernel.o" "$PWD/reverse-kernel.o" 50
python3 run.py --implementations forward reverse --phase full
```

本机重算完整50样本统计：

```sh
python3 verify/rvv_q3_gemm/summarize.py /path/to/results
```

未删除慢样本。跨方向耗时包含目标硬件和源VLEN分支差异，优化收益应在同一方向、
同一输入及硬件条件下交错比较优化前后版本。函数参考/canary门禁与逐指令全状态差分
分别保留，不把主函数输出检查替代寄存器、CSR回归。


进程内消融使用两套独立 TLS 状态和 AB/BA 顺序。先以 `--translator-root` 指定优化前源码生成基线对象，候选对象使用当前源码生成。板端在同一 payload 目录中执行：

```sh
sh build_paired.sh forward /path/to/baseline-forward.o /path/to/candidate-forward.o 50
python3 run_paired.py --direction forward --samples 50
sh build_paired.sh reverse /path/to/baseline-reverse.o /path/to/candidate-reverse.o 50
python3 run_paired.py --direction reverse --samples 50
```

两份对象只重命名函数和 TLS 符号，并统一 `.text` 为64字节入口对齐；原对象保留。每个样本单独核对所有 worker 和输出/输入/canary，原始 batch 时间与每次调用时间均保留。20对消融将 build 和 run 的样本数都改为20。重算配对统计：

```sh
python3 verify/rvv_q3_gemm/summarize_paired.py /path/to/results
```

主 GEMM 的逐指令 MAC 门禁通过 `statecheck.py` 生成 C、native/translated 汇编、case 清单和指纹：

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 python3 verify/rvv_q3_gemm/statecheck.py \
  --direction forward --out /path/to/state-forward
PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 python3 verify/rvv_q3_gemm/statecheck.py \
  --direction reverse --out /path/to/state-reverse
```

源原生参考在对应源核生成，目标在对应目标核比较，参考文件放在板端 ext4。正向非零模拟 `vstart` 使用 native-zero 交叉验证的独立 scalar restart oracle；原生探针、保留编码布局控制及检查边界见已接入结果；完整实验产物保留在K3。
