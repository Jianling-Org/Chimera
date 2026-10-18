# 协议与 ABI

当前正式协议定义集中在[开发者ABI文档](../developer/abi/README.md)：Manifest、运行时、安全表、offset map、编译器元数据与BPF注册接口。

自动迁移的 live signal-frame 捕获、可选 no-link metadata、非零vstart拒绝以及失败回退见[状态机](../architecture/automigration.md)。新增可选扩展不能使旧工件被当作具备新能力；装载前验证场景、版本、数量、边界与内容身份，缺失能力时拒绝对应路径。
