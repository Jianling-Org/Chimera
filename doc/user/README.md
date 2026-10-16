# 应用使用者指南

应用使用者负责在目标机安装交付的 Chimera wheel、应用和 `.workspace` 包，验证环境、注册实际文件、启动应用，并在运行时就绪后请求线程迁移。无需应用 Profile、应用源码或离线翻译器。

当前目标为 Linux / RISC-V64 / RVV，需要匹配的内核/BPF 配套、可访问的注册 map 与迁移控制接口。应用及目标解析依赖须由应用原有安装方式预先装好，内容必须匹配工件包；包内提供 scalar 底座和运行工件，不能代替应用安装。

## 最短运行流程

```bash
python3 -m pip install "$CHIMERA_WHEEL"
chimera-pkg workspace install --input "$WORKSPACE_PACKAGE" --name application
ELF=/path/to/installed/application
chimera-user list
chimera-user verify --workspace application
chimera-user register --workspace application --input "$ELF"
chimera-user run --workspace application --input "$ELF" -- APPLICATION_ARGUMENTS
```

替换 `APPLICATION_ARGUMENTS` 为实际参数；无参数时省略。`run` 显式调用包内 scalar loader，以应用原位置的 ELF 启动进程。`chimera-user` 通过 `execve` 将自身替换为 loader/应用，最终退出状态来自 loader/应用；从交互 shell 执行时，父 shell 保留。

需要迁移时，先在另一终端确认 Runtime 初始化完成并识别计算线程，再执行 [迁移命令](cli.md#迁移线程)。存在 PID、Workspace 环境变量或应用已打印启动消息均不足以证明 Runtime ready。CLI 会检查每个目标线程的处理器和信号屏蔽状态；未就绪时应等待初始化完成后重试。

迁移命令返回 0 表示请求已提交。是否完成迁移须结合应用结果、Runtime 事件和线程所在核判断；`migrated_tids[...]` 记录提交的 TID，不是完成确认。

## 导航

- [使用者 CLI：设置、校验、注册、启动、迁移和失败](cli.md)
- [Workspace 安装及资源规则](../integration/workspace.md)
- [安全点与验收边界](../developer/architecture/safepoints/README.md)
- 应用参数与结果检查：[Hello World](../../examples/applications/hello-world/README.md)、[llama.cpp](../../examples/applications/llama-cpp/README.md)、[GCC](../../examples/applications/gcc/README.md)、[OpenMP 算子探针](../../examples/applications/omp-kernel-probe/README.md)

[返回发布文档](../README.md)
