# Chimera

Chimera 支持 RISC-V 向量应用在线程迁移时转换向量状态，使应用能够在不同向量长度的处理器之间运行。系统离线检查并翻译应用的 ELF 文件，将翻译代码、安全点和运行时打包为 Workspace；目标机加载 Workspace 后执行应用和线程迁移。

当前支持 Spacemit K3 上 X100（CPU 0–7，VLEN 256）与 A100（CPU 8–15，VLEN 1024）之间的双向自动迁移。

## 开始使用

按需要选择以下入口：

| 任务 | 文档 |
|---|---|
| 构建 Chimera、编译器插件和运行时 | [构建与测试](docs/developer/build-and-test.md) |
| 准备目标机内核和控制接口 | [K3 内核支持](kernel/README.md) |
| 检查应用并生成 Workspace | [应用集成指南](docs/deployment/README.md) |
| 安装 Workspace 并运行应用 | [在目标机运行应用](docs/user/README.md) |
| 构建与运行 llama.cpp | [llama.cpp 示例](examples/applications/llama-cpp/README.md) |

按任务阅读[Chimera 文档](docs/README.md)，或查阅[完整目录](docs/INDEX.md)。

## 应用准备流程

开始前，安装 Chimera 及配套工具链，并为应用准备 Profile 配置和依赖。以下命令在应用集成环境中执行：

```bash
PROFILE=/absolute/path/to/application.toml
ELF=/absolute/path/to/application
WORKSPACE=application

chimera-pkg check-elf --strict --profile "$PROFILE" --input "$ELF"
chimera-pkg prepare --profile "$PROFILE" --input "$ELF" --workspace "$WORKSPACE"
chimera-pkg workspace pack --workspace "$WORKSPACE" --output application.workspace
```

`prepare` 生成应用 Workspace，`workspace pack` 输出当前目录下的 `application.workspace`。严格检查通过后再执行 `prepare`。检查报告要求补充编译器元数据或 gate 重编时，按[检查与重编指南](docs/deployment/cli.md#固定重编计划)处理，然后重新检查最终 ELF。

Gate 对决策清单中的函数禁用 Loop/SLP 自动向量化及匹配的内存操作 lowering；其他计算路径可以继续使用 RVV。Gate 构建需要配套的 LLVM 补丁、VectorGate 插件和编译包装器。详见 [Gate 构建](docs/deployment/gate-build.md)。

生成的 `application.workspace` 与对应应用版本一同交付到目标机。目标机需要匹配的内核、BPF 环境和运行时；安装、注册及启动步骤见[在目标机运行应用](docs/user/README.md)。

## 验证

源码回归测试使用 `make python-test` 和 `make portable-c-test`。K3 自动迁移的测试配置、结果和适用范围见[自动迁移验证](docs/validation/automigration.md)。

## 项目结构

| 目录 | 内容 |
|---|---|
| `preprocessing/` | 离线分析、翻译器及编译器插件 |
| `runtime/` | 运行时、BPF、启动与工件管理 |
| `kernel/` | K3 内核补丁、配置和构建工具 |
| `examples/` | 应用配置、构建和运行示例 |
| `docs/` | 用户指南、开发文档和接口参考 |
| `third_party/` | 第三方源码引用 |
| `cli/`、`tools/`、`tests/` | 命令行工具、辅助工具和测试 |

参与开发见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 版权与许可

各组件按逐文件许可证分发。ISCAS 内核贡献的版权范围见 [COPYRIGHT](COPYRIGHT)，组件许可见 [LICENSES](LICENSES/README.md)。
