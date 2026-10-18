# 当前 A100 IME→RVV 实现与验证

> 历史专项实验记录：下列测试数量和性能仅适用于文中日期、输入与构建，适用的输入和配置以各节记录为准。自动迁移验证见[独立验收记录](../../../../../docs/validation/automigration.md)。

2026-10-12。仓库只保留当前优化后的生产 lowering，没有旧版策略或优化等级开关。
严格逐指令 1:N，普通 RVV 原生执行；支持基础 Int4/Int8、Int8 滑窗和六种重排。
Int8 使用 K-major 工作副本、VL=32、B 复用、两移位字节提取，以及目的寄存器不冲突时直接累加。
pack 使用标量拷贝，仅借用 t0/t1，不改 VL/VTYPE；各指令独立完成状态恢复。

## 状态验证

当前完整工作区测试为 1681 passed、41 skipped。41 项分别需要 ld.lld（28）、
Linux ELF loader（12）或 Linux/RV64 loader（1）。同步提交在干净 HEAD 加本次文件清单上验证：**1648 passed、41 skipped**，
跳过原因相同；两者数量差异来自未纳入本次同步的其他暂存测试。
QEMU 全状态 130050 次通过；A100 原生整数配对 58080 次执行（29040 对）通过，
全部支持形式的翻译版独立参考 109980 次通过。覆盖所有偶数目的寄存器和结果依赖，
检查全部向量、GPR/FPR、SP、VL/VTYPE/VSTART/VCSR/FCSR 及 canary。
零/短 VL 与重排别名属于软件契约验证；原生整数配对覆盖满 VL。

## 四形状性能

单位 **ms / 完整算子调用，Gaussian KDE 众数**。CPU8-15，8 线程，VLEN1024，
userspace 1.8GHz；本轮采样的全部频率记录均为 1800000 kHz。
沿用原驱动、原 RVV/IME 对象、四份参考文件和输入，原始对象 SHA256 核对一致。
保持原静态分块、bs=N+16、3 次预热、pilot 校准、每形状 50 样本、CLOCK_MONOTONIC_RAW。
计时包含 OpenMP 调度，不包含准备、packing 和参考计算。KDE 使用 Scott 带宽，未删除样本。

前三个性能列复用同一 A100、同一口径的原始 50 轮结果；最后一列为本次正式 lowering 新测。
“最初未优化”指第一版 IME→RVV，累计加速包含前几批优化，并非本次两项的单独收益。

| 用途 | MxNxK | 原生 IME | 原生 RVV | 最初未优化 IME→RVV | 本次正式优化 | 累计翻译加速 | 本次/RVV |
|---|---|---:|---:|---:|---:|---:|---:|
| FFN gate/up | 32x5632x2048 | 1.758904 | 6.970733 | 3294.193962 | 79.206031 | 41.59x | 11.36x |
| FFN down | 32x2048x5632 | 1.778338 | 6.970434 | 3343.300334 | 79.350021 | 42.13x | 11.38x |
| Attention Q/output | 32x2048x2048 | 0.591108 | 2.364481 | 1268.499765 | 28.866625 | 43.94x | 12.21x |
| Attention K/V | 32x256x2048 | 0.070771 | 0.272826 | 158.611999 | 3.596921 | 44.10x | 13.18x |

四形状均 max_abs_error=0，输出哈希与原生 IME 相同，输入、padding 和 canary 完整。
历史性能数字用于比较，不随附旧翻译策略、诊断候选或历史生成汇编。
当前仍比原生 RVV 慢 11.36-13.18 倍。

## 保留证据

- [当前 200 个原始样本及环境](int8-opt4-results/int8_opt4-full-results.json)
- [KDE 对比统计](int8-opt4-results/comparison-summary.json)
- [干净提交范围测试日志](int8-opt4-results/isolated-pytest.log)
- [本轮工作区测试日志](int8-opt4-results/pytest.log)
- [原生配对日志](int8-opt4-results/state-integer/result.stdout)
- [全部形式独立参考日志](int8-opt4-results/state-all/result.stdout)
- [二进制与参考指纹](int8-opt4-results/binaries.sha256)

上述目录名称只是测量记录标识，不是翻译路径。生成汇编、ELF、对象、板端 payload、
旧策略源码和诊断后处理脚本均不包含在本次同步中。生成及运行步骤见 [README.md](README.md)。
