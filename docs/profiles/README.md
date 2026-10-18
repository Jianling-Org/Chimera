# Profile 配置

[应用Profile指南](../deployment/profiles.md)说明输入模块、依赖、scalar根、工具、译器路线和workflow步骤。应用Profile用于离线检查和准备；已交付Workspace的运行用户使用Manifest与实际输入身份。

同一应用最终检查与prepare必须使用同一份安全参数。`assume-scalar-independent`及外部scalar-leaf契约属于显式条件范围，不能在声明结果时隐藏；参考范围见[未知栈尺寸策略](../developer/unknown-stack-size-scope.md)。

双向Profile必须包含两方向翻译绑定与步骤。源码中的个人路径或占位绝对路径需要按当前机器替换，并保存实际使用的完整Profile及哈希。Gate重编要求见[构建约束](../deployment/gate-build.md)。
