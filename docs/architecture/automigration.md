# 双向自动迁移与失败回退

当前 K3 实现跨两组 CPU 迁移线程：X100（CPU 0–7，VLEN=256）和 A100（CPU 8–15，VLEN=1024）。迁移需要同时处理 CPU 放置、PC 对应的代码 variant、通用/浮点寄存器、向量状态和后续安全点返回。

## 状态机

允许的执行序列为 source original → 对应方向 translated → target original。完整往返为 original 1024 → translated 1024-to-256 → original 256 → translated 256-to-1024 → original 1024。Translated body 是过渡执行区域，不能再次迁移；缺少路线、映射或安全元数据时拒绝准备。

主线程与工作线程可以参加自动迁移，使用同样的准备和提交规则。不能仅凭线程角色断言安全，也不能把 affinity 切换当作完整 Chimera 状态转换。

## proposal、准备与提交

内核保留分组账本、pending、generation、目标 CPU reservation、超时、退出/exec 取消和 stopper 最终复验。睡眠线程仍占账本槽位。用户态收到 proposal 后，从实际 signal frame 捕获源上下文，检查当前 original body、目标路线及可保存状态，成功准备后才提交 ACK。

准备失败返回相应 NACK，并保留源 CPU、PC 和完整上下文。内核提交失败也不得将用户线程暴露为半完成状态。成功写入 proposal 或观察到预提交 rewrite 意图，都不能直接计为成功迁移；必须关联成功 COMMIT ACK、内核完成计数和 translated 退出。

proposal 与 safepoint 信号必须串行处理，防止同时更改 PC、信号帧或每线程过渡状态。退出任务不得重新注册；reservation 所有权必须释放，不能只因时间戳过期就忽略仍被占用的槽位。

## 非零 vector restart index

源向量指令可能被中断于非零 `vstart`。当前 translated 向量内存 lowering 不能从任意非零 restart index 恢复，因此 `chimera_scene_save_vector_state` 在写 translator TLS 和提交 ACK 之前拒绝此类准备。处理器返回 PREPARE NACK，保留原 signal frame；sigreturn 在源位置按原 restart index 继续执行，后续 proposal 可以在源程序取得进展后再尝试。

不能清零 `vstart`、移除译器 trap 或放宽 checker 来隐藏这一限制。该拒绝在两方向一致，legacy packed state ABI 保持原样。

## 无链接跳转分派

迁移可能在函数中途进入 translated body，返回地址仍指向原始调用者。translated RET/JR/JALR 的已验证目标发生变化时，使用 variant 范围内的可选 no-link metadata：ABI=1、计数以及每项32字节的精确 trap PC、query frame 大小、target slot 偏移和原指令 RVA。

译器保存已解析目标，恢复 GPR/FPR/FCSR，并保留描述好的 query frame。SIGTRAP handler 仅接受已注册的精确站点，验证目标稳定、非零、偶地址且不递归到自身，弹出已知 frame 后改 PC；其余上下文保持。此操作不迁移 CPU、不切换 translated variant、不发送 ORIGINAL ACK。未知、无效或不稳定目标继续 fail closed。没有扩展表的旧 DSO 保留原失败行为。

## 动态验收口径

逐 TID 关联 successful COMMIT ACK → 进入正确 translated route → 已验证退出到 original；与内核 source/destination CPU trace 和完成计数一致。必须无 translated 重入、无退出时 pending、无 trace 覆写，数值输出与固定原生对照结果在声明容差内。检查每轮线程覆盖、前后五类账本清零和新增内核告警。

缩减双向往返、真实 llama 线程矩阵、十轮16线程与实际两小时混合负载分别提供不同覆盖，不能相互替代。当前轮次的结果由独立验收摘要记录，历史诊断和可移植单测不作为最终动态通过证明。
