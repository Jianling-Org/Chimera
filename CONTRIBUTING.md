# 开发与验证

从 [开发入口](docs/developer/README.md) 和 [构建测试](docs/developer/build-and-test.md) 开始。变更按运行逻辑、接口、测试、文档分别组织，提交说明写清触发条件与验证范围。

自动迁移改动必须保持 [状态机](docs/architecture/automigration.md)：translated body不可再次迁移，准备或提交失败保留源CPU、PC和上下文。内核安装前需要审查锁顺序、task生命周期、reservation泄漏和signal frame一致性。

`make python-test` 和 `make portable-c-test` 提供本地回归测试。RISC-V 迁移功能还需实机验证。目标验收要求缩减双向往返、真实线程矩阵、账本和告警检查、十轮16线程及实际两小时混合负载；输入、构建和安全假设改变时重新验证。

不要提交模型、生成Workspace、板端日志和个人目录。保留原作者与逐文件许可证，新增文件按所属组件添加许可证和适用的版权声明。平台与应用的验证范围见 [验收记录](docs/validation/automigration.md)。
