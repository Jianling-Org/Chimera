# Chimera

Chimera 为已有 ELF 应用生成离线分析与翻译工件，使线程能够在不同向量长度的执行环境之间转换。应用集成者准备并交付 Workspace，应用使用者通过运行时加载这些工件；在线运行不重放离线工作流。

当前提供的目标组合是 Linux、RISC-V64、RVV，运行场景为 `linux_riscv64_rvv_v1`，包含 `1024-to-256`、`256-to-1024`、`1024-256双向迁移` 三条迁移路线。目标机器需要配套的运行时、内核控制接口和 BPF 环境，具体条件见 [RVV 目标实现](developer/architecture/targets/rvv/README.md)。

## 选择阅读入口

| 角色 | 要完成的工作 | 主要命令 | 文档 |
|---|---|---|---|
| Chimera 开发者 | 实现与扩展系统，构建工具链和发布 wheel | `chimera-dev` | [开发者指南](developer/README.md) |
| 应用集成者 | 检查和适配应用，准备、打包与交付工件 | `chimera-pkg` | [集成指南](integration/README.md) |
| 应用使用者 | 安装工件，验证、注册、运行与迁移应用 | `chimera-user` | [使用指南](user/README.md) |

工具链构建所需的 LLVM/SVF 源码版本与准备步骤见 [LLVM 与 SVF 源码准备](external-dependencies.md)。

## 理解三种交付物

| 交付物 | 内容与用途 |
|---|---|
| Chimera wheel | 系统 Python 包、运行时源码以及发布所需的编译器和插件等资源，供安装系统能力 |
| Workspace 与 `.workspace` 包 | 针对确定应用内容准备的翻译代码、地址映射、安全点、运行时、Manifest 和随包底座模块 |
| 应用本身 | 由目标机器安装，留在应用自己的位置；实际文件内容必须与准备时匹配 |

Workspace 不携带应用主程序。准备阶段选择的 scalar 加载器和 scalar 依赖随包交付，其余依赖在目标机器解析；选择结果与摘要记在 Manifest 中。运行时通过内容校验确认实际加载文件与离线输入一致。详见 [Workspace 交付](integration/workspace.md)。

## 最短交付流程

先在构建机安装 Chimera，并按 [Profile 指南](integration/profiles.md) 准备应用配置、工具和模块依赖。以下命令中的路径是待替换的通用示例；检查发现问题时先完成 [检查与重编](integration/cli.md#固定重编计划)。

```bash
chimera-pkg check-elf --strict --profile ./application.toml --input ./app
chimera-pkg prepare --profile ./application.toml --input ./app
chimera-pkg workspace pack --workspace ID_OR_PATH --output ./app.workspace
```

在满足目标条件的机器上安装同一应用及 Chimera 后，安装工件包并运行：

```bash
chimera-pkg workspace install --input ./app.workspace
chimera-user verify --workspace ID_OR_PATH
chimera-user register --input /path/to/app
chimera-user run --input /path/to/app -- APPLICATION_ARGS...
```

`verify` 检查安装与运行环境契约。`register`、`run` 都核对主程序的文件名和内容，`run` 还会校验加载器报告的已记录依赖内容。应用使用者不需要应用 Profile、源代码或离线编译工具。迁移请求的线程选择、就绪条件和结果判断见 [使用者命令参考](user/cli.md)。

## 系统设计

- [架构总览](developer/architecture/README.md)：组件关系、数据流和职责边界。
- [安全点分析算法](developer/architecture/safepoints/README.md)：分析模型、分类规则、调用传播及条件范围。
- [扩展机制](developer/architecture/extensibility.md)：新增步骤、目标和运行时能力。
- [协议与 ABI](developer/abi/README.md)：Manifest、运行时、安全表、地址映射与编译器元数据。

扩展机制描述系统的接入方式。已提供的目标能力以具体目标实现为准，新增目标还需要离线、运行时及目标机验证。

## 应用样例

- [Hello World](../examples/applications/hello-world/README.md)：最小应用构建与工件流程。
- [llama.cpp](../examples/applications/llama-cpp/README.md)：源码、补丁、模型与应用适配。
- [GCC](../examples/applications/gcc/README.md)：编译器驱动与编译子程序的适配。
- [OpenMP 算子探针](../examples/applications/omp-kernel-probe/README.md)：真实并行调用链与日志口径。


## 翻译器

- [翻译器使用方法](integration/translator.md)
- [翻译器架构](developer/architecture/translator.md)
