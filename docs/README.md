# Chimera 文档

Chimera 为 RISC-V 向量应用生成离线检查与翻译工件，并通过运行时和配套内核实现跨向量长度的线程迁移。当前支持 Spacemit K3 的 X100（VLEN 256）与 A100（VLEN 1024）。

## 安装、集成与运行

| 任务 | 阅读入口 |
|---|---|
| 安装源码开发环境并构建工具链 | [构建与测试](developer/build-and-test.md) |
| 准备 K3 内核 | [K3 内核支持](../kernel/README.md) |
| 准备 LLVM、SVF、应用源码和运行依赖 | [外部依赖与源码版本](external-dependencies.md) |
| 检查应用并生成交付包 | [应用集成指南](deployment/README.md) |
| 在目标机安装工件并运行应用 | [运行指南](user/README.md) |
| 修改或扩展 Chimera | [开发者指南](developer/README.md) |

## 基本概念

- **Profile**：TOML 格式的应用配置，指定目标、工具、依赖和离线处理步骤。
- **Workspace**：针对应用生成的翻译代码、安全点、运行时、Manifest 及选定依赖。`.workspace` 是其可安装归档；应用主程序由目标机单独安装。
- **Runtime**：目标机运行时，负责装载工件、维护线程状态并配合内核完成迁移。
- **Gate**：按函数决策限制编译器隐式向量化的构建机制，详见 [Gate 构建](deployment/gate-build.md)。

构建机按 Profile 生成 Workspace，目标机安装工件包后运行应用。运行阶段核对应用和依赖的内容身份，使用者无需 Profile 或离线编译工具。文件布局与校验规则见 [Workspace 打包与安装](deployment/workspace.md)。

## 应用样例

- [Hello World](../examples/applications/hello-world/README.md)：最小构建与工件流程。
- [llama.cpp](../examples/applications/llama-cpp/README.md)：应用构建、模型与依赖准备。
- [llama.cpp 双向自动迁移](../examples/applications/llama-cpp/reference-v32/README.md)：多线程配置与验证。
- [GCC](../examples/applications/gcc/README.md)：编译器驱动及子程序适配。
- [OpenMP 算子探针](../examples/applications/omp-kernel-probe/README.md)：并行调用链与迁移观测。

各示例的准备条件和验证范围见对应页面。K3 自动迁移的已测配置与结果见[自动迁移验证](validation/automigration.md)。

## 开发参考

- [架构总览](developer/architecture/README.md)：组件与离线、在线数据流。
- [安全点分析算法](developer/architecture/safepoints/README.md)：分析模型与分类规则。
- [双向自动迁移](architecture/automigration.md)：状态转换、安全条件和失败回退。
- [协议与 ABI](developer/abi/README.md)：Manifest、安全表、地址映射和编译器元数据。
- [扩展机制](developer/architecture/extensibility.md)：新增处理步骤、目标和运行时能力。

全部页面见[完整文档目录](INDEX.md)。
