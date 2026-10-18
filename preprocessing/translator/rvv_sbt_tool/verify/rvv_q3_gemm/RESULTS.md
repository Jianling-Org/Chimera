# 双向 RVV 主 GEMM 已接入优化与验收

> 历史专项实验记录：下列测试数量和性能仅适用于文中日期、输入与构建，适用的输入和配置以各节记录为准。自动迁移验证见[独立验收记录](../../../../../docs/validation/automigration.md)。

2026-10-14。主算子为 `ggml_gemm_q3_K_64x1_q8_K`，保留四形状、8线程及原输入/参考、量化布局与 worker 划分。
正向在 X100 CPU0–7、VLEN256、2.2GHz，反向在 A100 CPU8–15、VLEN1024、1.8GHz。源1024/256分别运行VL64/VL16分支。

## 正式翻译路径

正向无掩码 `vfwmacc.vv`、e16/m1 `vmacc.vx`/`vwmacc.vv`、e32/m8 `vfmacc.vv`/`vle32.v` 固定使用已验收实现，宽与保守 profile 生成相同热点翻译。旧 `vfwmacc.vv` 小块/标量尾部 builder 已删除。其他形态按其寄存器容量与 mask 语义保留适用实现。
反向活动元素搬运、紧凑 LMUL、guard 临时寄存器复用、条件 vcsr 同步及 vmacc 地址保留直接接入正式 lowerer，没有优化开关或历史实现选择。
每条源指令独立完成 guard、输入读取、执行和即时状态提交；旧累加器、关闭的 mask lane、tail、GPR/FPR 及模拟/实际 CSR 均保持验证合同。Runtime ABI 不变。

## 累计历史耗时

单位ms/完整调用，Gaussian KDE全局众数、Scott带宽，保留每版本50样本。累计下降=100*(1-current/baseline)，加速比=baseline/current。
起点是2026-10-13主GEMM专项优化前的正式基线，已包含此前点积阶段的通用优化；没有这些通用优化接入前的四形状主GEMM数据，因此不能称为全部历史优化从零开始的总收益。
这两端为跨批次历史比较，不是最终版与最初版在同进程内重新配对；两译向运行于不同硬件，不能直接取两列比值作为lowering成本。

### 正向 RVV1024→RVV256

| 用途 | M×N×K | 专项优化前 | 已接入版本 | 耗时下降 | 加速比 |
|---|---|---:|---:|---:|---:|
| FFN gate/up | 32×5632×2048 | 38.896843 | 37.264931 | 4.195% | 1.0438× |
| FFN down | 32×2048×5632 | 39.114533 | 36.869934 | 5.739% | 1.0609× |
| Attention Q/output | 32×2048×2048 | 14.275729 | 13.514872 | 5.330% | 1.0563× |
| Attention K/V | 32×256×2048 | 1.787962 | 1.691130 | 5.416% | 1.0573× |

### 反向 RVV256→RVV1024

| 用途 | M×N×K | 专项优化前 | 已接入版本 | 耗时下降 | 加速比 |
|---|---|---:|---:|---:|---:|
| FFN gate/up | 32×5632×2048 | 638.266980 | 445.303499 | 30.232% | 1.4333× |
| FFN down | 32×2048×5632 | 644.425732 | 447.054331 | 30.627% | 1.4415× |
| Attention Q/output | 32×2048×2048 | 231.823294 | 161.582545 | 30.299% | 1.4347× |
| Attention K/V | 32×256×2048 | 28.945969 | 20.169645 | 30.320% | 1.4351× |

正向第二至第六批汇编均逐字节不变，沿用第一批样本。同进程配对确认的正向收益为2.66%–3.81%；它与历史绝对耗时降幅的差异包含批次/代码布局影响，不是后续新增收益。

## 分批配对验收

下表为各批相对本批起点的配对中位耗时下降。独立TLS、64B入口对齐、AB/BA顺序，3次预热、约100ms批次、CLOCK_MONOTONIC_RAW；每样本计时外检查reference、输入/canary/state和每worker CPU/affinity/vlenb/频率。各批收益不能直接相加。

| 批次 | 正式接入 | 正向 | 反向 | 最终50对数据 |
|---|---|---:|---:|---|
| 1 | MAC宽搬运/活动提交、执行LMUL、guard地址复用 | 2.66%–3.81% | 2.02%–2.26% | [统计及原始样本索引](results/batch1-20261013/aligned-50pairs/summary.json) |
| 2 | vand/shift活动输入与提交、热点GPR及vstart维护 | 汇编未变 | 9.51%–9.61% | [统计及原始样本索引](results/batch2-20261013/final/summary.json) |
| 3 | 通用guard复用、条件vcsr写、首条vset清零vstart | 汇编未变 | 15.96%–16.74% | [统计及原始样本索引](results/batch3-20261013/final/summary.json) |
| 4 | masked add/zero extend Pack/Unpack、MAC闲置GPR | 汇编未变 | 5.24%–5.37% | [统计及原始样本索引](results/batch4-20261014/final/summary.json) |
| 5 | vmacc省去guard已证明为零的模拟vstart重复写回 | 汇编未变 | 2.59%–4.68% | [统计及原始样本索引](results/batch5-20261014/final/summary.json) |
| 6 | vmacc在死VL临时寄存器中保留目的地址 | 汇编未变 | 0.71%–0.88% | [统计及原始样本索引](results/batch6-20261014/final/summary.json) |

## 正确性与同步验证

六批真实硬件数据分别通过函数参考与全状态差分。最新反向正式方案26,298条状态比较、9个guard探针通过；1140个source PC和399个guard trap保留。四形状最终200对全部改善，max_abs_error=0。完整实验对象、参考与perf data保留在报告中的K3目录；仓库不保存历史翻译实现、实验候选源代码或板端生成二进制。
本次独立交付快照：1828 passed、41 skipped；backend quality与支持文档一致性检查通过。重新生成的两条主GEMM汇编、kernel及驱动与第六批实测版本逐字节一致；反向70 case的状态门禁在相同硬件vstart=7入口下也与已验收文件逐字节一致。
[专项优化前基线](results/baseline-audit-20261013/summary.json)、[第六批硬件验收](results/batch6-20261014/acceptance.json)、[逐条1:N审计](results/batch6-20261014/one-to-n-audit.json)、[同步字节与测试核对](results/sync-20261014/verification.json)。
性能结论限于四个完整算子调用；反向仍有逐条状态与寄存器保护成本，未外推整模型或Runtime在线迁移性能。
