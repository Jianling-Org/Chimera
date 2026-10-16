# 应用集成者指南

应用集成者负责把应用 ELF、依赖和迁移场景变成可安装的 `.workspace` 工件包，并交付对应应用版本、运行参数和验收依据。应用使用者只消费交付结果，无需读取 Profile。

当前实际目标为 Linux / RISC-V64 / RVV，运行场景为 `linux_riscv64_rvv_v1`。开始前准备匹配目标的 Chimera wheel、应用及其依赖和 Profile 指定的工具。每个 Workspace 按应用选择要随包交付的标量模块；Profile 的 `translator_path` 指向 Chimera 源码树中 `preprocessing/translator/rvv_sbt_tool/` 下的翻译器入口，使用方法见该目录的 `README.md`。`prepare` 还需要可生成目标代码的编译器、支持目标的 `objdump`/`nm`、CMake 和相应开发依赖。wheel 不提供全部开发工具，不能假设其中包含 `llvm-objdump`、`opt`、`llc` 或完整 SVF。

## 最短交付流程

以下命令在集成环境中执行。`PROFILE` 指向完整 TOML，`ELF` 指向最终交付的应用，`WORKSPACE` 是本次发布名称；先按 [Profile](profiles.md) 配好目标、依赖与工具。

```bash
PROFILE=/path/to/application.toml
ELF=/path/to/application
WORKSPACE=application
chimera-pkg check-elf --profile "$PROFILE" --input "$ELF" --strict
chimera-pkg prepare --profile "$PROFILE" --input "$ELF" --workspace "$WORKSPACE"
chimera-pkg workspace pack --workspace "$WORKSPACE" --output application.workspace
```

若严格检查返回 1，读取检查报告并按 [CLI 的固定重编计划](cli.md#固定重编计划) 修复，再检查最终 ELF；不要继续套用上面的成功分支。`prepare` 要求当前 ELF 内容与当前 workflow 的检查凭据一致，编译器修复后的 `REMEDIATED` 状态也需要复检。

在目标机预安装同内容的应用及由目标机解析的依赖，再安装工件包并执行使用者的 `verify/register/run` 流程。输入 ELF 不改写，应用不随包；包内 scalar loader 在启动时被显式调用。

## 阅读顺序

- [CLI：检查、固定重编、准备和构建说明包](cli.md)
- [Profile：字段、默认值、workflow 与当前目标例子](profiles.md)
- [Workspace：内容、resources、打包和安装](workspace.md)
- [应用使用者指南](../user/README.md)
- [安全点与安全检查](../developer/architecture/safepoints/README.md)

应用专属源码、补丁、模型和构建命令放在样例目录：[Hello World](../../examples/applications/hello-world/README.md)、[llama.cpp](../../examples/applications/llama-cpp/README.md)、[GCC](../../examples/applications/gcc/README.md)、[OpenMP 算子探针](../../examples/applications/omp-kernel-probe/README.md)。

[返回发布文档](../README.md)
