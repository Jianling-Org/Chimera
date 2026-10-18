# 应用集成指南

本指南说明如何检查应用、生成 Workspace 并打包交付。Workspace 包含离线生成的翻译代码、安全点、运行时和选定依赖；应用主程序由目标机单独安装。

## 前提条件

- 已安装 Chimera，并准备目标架构的编译器、`objdump`、`nm` 和 CMake。
- 已准备应用的最终 ELF、依赖和标量运行库（scalar 底座）。
- 已配置 [Profile](profiles.md)，包括目标、翻译器、工具和依赖路径。

当前支持 Linux/RISC-V64/RVV，运行场景为 `linux_riscv64_rvv_v1`。需要重新编译应用时，先按[构建与测试](../developer/build-and-test.md)准备 LLVM 和插件；工具与外部库的来源见[依赖说明](../external-dependencies.md)。

## 检查应用

在集成环境中设置实际路径并运行严格检查：

```bash
PROFILE=/absolute/path/to/application.toml
ELF=/absolute/path/to/application
WORKSPACE=application

chimera-pkg check-elf --strict --profile "$PROFILE" --input "$ELF"
```

检查通过时退出状态为 0。退出状态为 1 时，读取报告，按[固定重编计划](cli.md#固定重编计划)补充元数据或执行 gate 重编，再检查最终 ELF。Gate 重编的工具链与按函数约束见 [Gate 构建](gate-build.md)。

## 生成并打包 Workspace

在同一 shell 中沿用上一节的 `$PROFILE`、`$ELF` 和 `$WORKSPACE`：

```bash
chimera-pkg prepare --profile "$PROFILE" --input "$ELF" --workspace "$WORKSPACE"
chimera-pkg workspace pack --workspace "$WORKSPACE" --output application.workspace
```

`prepare` 校验检查凭据与输入内容及工作流一致，然后生成运行工件。`workspace pack` 输出可交付的 `application.workspace`。

## 交付到目标机

向使用者提供工件包、匹配的应用和依赖版本、运行参数，以及必要的结果检查方法。检查使用条件假设时，同时交付 Profile、报告及假设的适用范围，详见[安全检查](../developer/architecture/safepoints/README.md)。目标机先安装应用与依赖，再按[运行指南](../user/README.md)安装包、验证环境、注册和启动应用。

Workspace 的文件布局、资源声明和完整性检查见 [Workspace](workspace.md)；各命令和参数见 [CLI 参考](cli.md)。应用专属步骤见 [Hello World](../../examples/applications/hello-world/README.md)、[llama.cpp](../../examples/applications/llama-cpp/README.md)、[GCC](../../examples/applications/gcc/README.md)和 [OpenMP 探针](../../examples/applications/omp-kernel-probe/README.md)。
