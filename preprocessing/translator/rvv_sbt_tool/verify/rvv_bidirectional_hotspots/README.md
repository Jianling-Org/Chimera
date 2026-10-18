# 双向 RVV 辅助热点与全状态回归

三个点积函数用于局部 profiling 与逐指令回归；性能主验收为
[`ggml_gemm_q3_K_64x1_q8_K` 四形状、8线程](../rvv_q3_gemm/RESULTS.md)。
正向已验收的 widening FMA、F32 load/FMA 和主 GEMM MAC 是正式主路径，
宽/保守 profile 使用相同热点实现。反向 CSR、活动元素提交和寄存器优化直接生效。
每条源指令独立读取、执行并立即提交模拟状态，保持寄存器、CSR 与 Runtime ABI。

| 短名 | 提取函数 | 源指令数 |
|---|---|---:|
| f32 | `ggml_vec_dot_f32` | 22 |
| f16 | `ggml_vec_dot_f16` | 23 |
| q5 | `ggml_vec_dot_q5_0_q8_0_generic` | 159 |

历史实验源 ELF 身份见[验证记录](../../../../../docs/validation/measured-artifacts.json)；以下固定地址与提取数据只适用于该输入。
反汇编及指纹见 [source-snapshot.json](source-snapshot.json)。保留完整标量控制流，
函数内部跳转按源PC重新绑定局部标签；不支持的提取依赖在生成时拒绝。

辅助点积测量使用一个线程、`nrc=1`、N=256/2048/8192。正向CPU0/X100、
VLEN256、2.2GHz；反向CPU8/A100、VLEN1024、1.8GHz。CLOCK_MONOTONIC_RAW，
先通过独立参考、输入及canary门禁，再计时。点积结果不替代主GEMM四形状结论。

生成当前翻译与逐指令状态门禁：

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 PYTHONPATH=.:src \
  python3 verify/rvv_bidirectional_hotspots/prepare.py \
  --sources verify/rvv_bidirectional_hotspots/source-snapshot.json --out /path/to/payload
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=.:src \
  python3 verify/rvv_bidirectional_hotspots/statecheck.py \
  --direction forward --out /path/to/state-forward
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=.:src \
  python3 verify/rvv_bidirectional_hotspots/statecheck.py \
  --direction reverse --out /path/to/state-reverse
```

`statecheck.c` 比较整个模拟状态、相关内存、非输出GPR/FPR、标量输出、FCSR、
实际vcsr/vstart及栈/状态/内存canary。先在源核运行native生成reference，再在目标核
运行candidate比较。目标物理向量临时组遵守现有clobber合同，源逻辑向量状态逐条提交。
原生参考、perf data与完整历史实验留存在K3；仓库只交付当前正式实现与复现工具。
