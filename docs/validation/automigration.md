# 自动迁移验证

Spacemit K3 上的双向自动迁移验证通过。验证采用下述固定输入和条件安全 Profile，检查结论为 **conditional**。被测源码、镜像身份与日志摘要见[结果 JSON](automigration.json)，应用与依赖的实测身份见[产物记录](measured-artifacts.json)。这些摘要仅关联已有测试结果，不作为独立构建的预期输出。

| 门槛 | 结果 |
|---|---|
| 缩减双向 RVV | 3轮通过，同一TID双向往返，24 worker校验一致 |
| llama矩阵 | 2/4/8/12/16/24/32线程，7轮通过 |
| 十轮16线程 | 10轮通过 |
| 两小时混合线程 | 实际7227.387940秒、106轮通过 |
| PPL | 原生与全部123轮llama均12.7757，预设绝对容差0.01 |
| 混合实际迁移 | 256→1024为106次，1024→256为580次 |
| 状态链 | 每轮原始成功ACK、逐TID内核CPU trace及runtime记录独立重放一致 |
| 清理与告警 | 五项账本归零，全程内核日志连续、无新增告警 |

主线程允许迁移，123轮llama均观测到实际主线程迁移。非零vstart安全拒绝在mixed-0034-32真实触发一次（vstart48/vlenb128/vl64），程序继续并正常完成。未观察到translated body重入迁移；32个Workspace工件身份在运行前后不变。

边界：固定TinyLlama Q3_K_S、固定语料、context/batch512、ubatch128、chunks1、seed1234；混合的是线程数量，不是多个模型或上下文大小。Profile依赖assume-scalar-independent和绑定libc身份的memset scalar-leaf契约、min_vlen256。参考ELF使用OpenMP ON及1245名字gate，重编后strict通过。其他应用和构建配置需要按相同流程验证；吞吐性能应单独测量。

结构化结果记录各阶段日志归档的 SHA256，可用于核对验证证据。输入准备方式见[应用示例](../../examples/applications/llama-cpp/reference-v32/README.md)。
