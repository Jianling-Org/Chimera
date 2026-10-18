# 在目标机运行应用

本指南说明如何安装 Workspace、注册应用并启动进程。运行阶段使用已生成的工件包，不需要应用 Profile、应用源码或离线翻译器。

## 前提条件

准备以下文件和环境：

- 与目标平台匹配的 Chimera wheel 和 `.workspace` 包。
- 与工件包匹配的应用及目标机依赖。
- 已配置的 [K3 内核](../../kernel/README.md)、BPF 注册 map 和迁移控制接口。

Workspace 提供 scalar 底座和运行工件；应用本身仍按其原有安装方式安装。

## 安装与验证

将以下路径替换为实际文件：

```bash
CHIMERA_WHEEL=/absolute/path/to/chimera.whl
WORKSPACE_PACKAGE=/absolute/path/to/application.workspace
ELF=/absolute/path/to/installed/application

python3 -m pip install "$CHIMERA_WHEEL"
chimera-pkg workspace install --input "$WORKSPACE_PACKAGE" --name application
chimera-user list
chimera-user verify --workspace application
```

`list` 列出已安装的 Workspace。`verify` 检查工件和运行环境，通过时退出状态为 0；失败时先根据错误信息修正环境。

在同一终端沿用 `$ELF`。`register` 将应用实际文件的 inode 登记到内核，随后由 `run` 启动：

```bash
chimera-user register --workspace application --input "$ELF"
chimera-user run --workspace application --input "$ELF" -- APPLICATION_ARGUMENTS
```

将 `APPLICATION_ARGUMENTS` 替换为应用参数；无参数时省略。`run` 使用包内标量加载器启动应用，最终退出状态来自应用或加载器。应用及已记录依赖的内容必须与准备 Workspace 时一致。

## 线程迁移

自动迁移需要内核策略、BPF 触发器和 Runtime 均已配置。策略配置见应用内核补丁后的 `Documentation/scheduler/prefer-a100.rst`，触发器加载见 [BPF 触发器](../../runtime/bpf/trigger/README.md)。手动请求迁移时，在另一终端等待 Runtime 初始化完成，再按[迁移线程](cli.md#迁移线程)选择线程并提交请求。

迁移命令返回 0 表示请求已提交。确认迁移完成还需要检查 Runtime 事件、线程所在处理器及应用结果。线程未就绪时，等待初始化完成后重试；具体诊断见 [CLI 参考](cli.md)。

## 后续阅读

- [运行命令参考](cli.md)：校验、注册、启动、迁移和失败处理。
- [Workspace](../deployment/workspace.md)：包内容、安装及资源规则。
- [自动迁移状态机](../architecture/automigration.md)：线程状态和失败回退。
- [llama.cpp](../../examples/applications/llama-cpp/README.md)：应用参数与结果检查示例。
