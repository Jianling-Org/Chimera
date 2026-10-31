# GCC/make 首轮有效构建对照（2026-10-22）

同一候选内核上，普通 X100 八核与自动迁移异构十六核均成功构建完整 Image。首对加速比 **1.185×**，耗时缩短 **15.60%**。这是一对按十六核→八核顺序运行的测量，不是最终稳定性验收或多轮统计结论。

| 条件 | 普通 X100 八核 | 自动迁移异构十六核 |
| --- | --- | --- |
| 并发 | `-j8`，CPU0–7 | `-j16`，采样 CPU0–15 |
| bootstrap | 不加载，无注册表和自动迁移 | no-runtime-sha-v3，承担全部运行时开销 |
| 完整 Image 构建 | 1050.931 秒（17分30.93秒） | 886.997 秒（14分47秒） |
| 退出码 | 0 | 0 |
| 迁移 | 统计完全不变 | X→A 1203 次，A→X 1381 次 |
| 账本、pending、reservation | 全部归零 | 全部归零 |
| 新 bad frame、崩溃、OOM、迁移 timeout | 无 | 无 |

两组使用同一重编 make、GCC15.2.0 regex 堆分配候选、同一源码清单、配置及固定 KBUILD 环境，运行内核均为 `6.18.3-chimera-bootstrap-exec-signal-depth-v1`。xgcc/cc1 的 conservative strict 已零发现、零待证明，无豁免或排除；之后生成并注册匹配 Workspace。

配置 SHA-256 为 `76a61b7db17939ab66a43169c33fabdb2c8e7bc4ff5b194a75ff069856f07b4d`，Image 为 `cc73c96fc95cbadf79945182fe70e22f8f7c82b49299b20886a177a8416b24db`。Image、vmlinux、System.map 均逐项哈希一致，检查见同目录 `artifact-comparison.json`。

十六核采样记录到 81 个 cc1 在两个 CPU 组运行；全程平均忙碌比例约 X100 81.85%、A100 87.88%。用户态加系统 CPU 时间为 11786.93 秒，八核为 7846.49 秒。十六核消耗更多累计 CPU 时间，不能把核数翻倍理解为性能必然翻倍；目前没有将增加的 CPU 时间全部归因于某个开销。

运行时不计算 SHA。此前已把内容校验和完整静态表验证移至离线注册；相同未变化文件通过身份缓存避免重复内容哈希，加载时检查身份和验证凭据。三个真实内核编译单元的 bootstrap 增量开销约 0.81%–2.01%，详见 `BOOTSTRAP-STARTUP-COST.zh-CN.md`。更早含逐执行全量校验的性能数据及异常时间戳轮次均不参与比较。

此前完整异构构建的 make 信号帧故障确实复现并留下 core。修复候选限制嵌套应用信号帧尚未返回时提交迁移；十轮嵌套 ACK 拒绝、exec 继承、64 对象正常迁移及本轮完整 make 构建通过。`siglongjmp` 跳过 sigreturn 可能使迁移保守阻止至 exec，仍是已知限制，不代表一般信号控制流已全部验证。

板端证据：`/root/kaiwen/chimera-gcc-bootstrap-build/evidence/signal-depth-v1/kernel-performance-v2`，含命令、源码/配置身份、逐核采样、资源统计、迁移账本、前后 dmesg、产物与 `comparison.json`。该页保留首对样本；后续[同16并发实验](../experiments/gcc-performance/k3-20261030/README.md)使用新的轮次和输入身份，不混合上述时间。
