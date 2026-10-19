# 涧灵（Jianling）

> **v0.1.0-preview.1 技术预览版**：涧灵面向 RISC-V 异构执行。本版聚焦 Spacemit K3 的 X100（VLEN 256）与 A100（VLEN 1024）之间的双向线程迁移，尚不面向生产部署。

不同 RISC-V 核心可能具有不同的指令集扩展和执行能力。涧灵的长期目标是把程序兼容与适配、运行状态转换、跨核迁移和调度协同连接起来，逐步减少应用针对每种核心组合重复改写的成本。当前发布的技术实现聚焦于 RVV 向量长度差异；长期目标不代表任意 ISA 组合或任意应用工作负载已经得到支持。

当前系统对应用 ELF 进行离线检查和翻译，生成 Workspace；目标机由 Runtime 与配套 K3 内核、BPF 触发器协作，使线程在 X100 与 A100 核心组之间自动迁移。系统也保留 `chimera-user migrate` 手动请求入口。自动迁移的状态机、失败回退及适用边界见[设计文档](docs/architecture/automigration.md)和[验证记录](docs/validation/automigration.md)。

## 技术路线概览

- **离线阶段**：检查应用 ELF，并按 Profile 中的约定做 RVV 翻译，生成 Workspace。Profile 是描述应用编译与迁移前提的配置文件；RVV 翻译是把向量指令适配到目标向量长度（VLEN）的过程。
- **目标机阶段**：Runtime 配合 K3 内核与 BPF 触发器，在 X100（VLEN 256）与 A100（VLEN 1024）核心组之间迁移线程。
- **辅助分析**：`preprocessing/conformance/` 提供 VLEN 逃逸检测，检查向量长度值是否经返回值、堆对象或全局变量传出；这一检查不替代应用集成检查或目标机迁移验证。
- 细节见[设计文档](docs/architecture/automigration.md)，此处不展开。

## 开始使用

源码安装需要 Python 3.11 及以上：

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e .
chimera-dev --help
chimera-pkg --help
chimera-user --help
```

安装 Python 命令不等于具备完整迁移环境。实际检查和打包还需要目标架构工具链、应用 ELF、Profile、相关依赖及工具链插件；目标机运行还需配套 K3 内核和 BPF 环境。准备步骤见[构建与测试](docs/developer/build-and-test.md)、[外部依赖](docs/external-dependencies.md)和[K3 内核支持](kernel/README.md)。

准备好这些输入后，可按[应用集成指南](docs/deployment/README.md)检查最终 ELF 并生成 Workspace（以下路径是占位示例）：

```bash
PROFILE=/absolute/path/to/application.toml
ELF=/absolute/path/to/application
WORKSPACE=application

chimera-pkg check-elf --strict --profile "$PROFILE" --input "$ELF"
chimera-pkg prepare --profile "$PROFILE" --input "$ELF" --workspace "$WORKSPACE"
chimera-pkg workspace pack --workspace "$WORKSPACE" --output application.workspace
```

若严格检查要求补充元数据或重编，应先按[检查与重编指南](docs/deployment/cli.md#固定重编计划)处理，再对最终 ELF 重新检查。**Workspace 不包含应用主程序**；目标机须另行安装与 Workspace 匹配的应用及依赖，并按[运行指南](docs/user/README.md)部署。可以从 [Hello World 示例](examples/applications/hello-world/README.md)了解完整样例。

## 文档导航

- [文档总览](docs/README.md) · [完整目录](docs/INDEX.md)
- [构建与测试](docs/developer/build-and-test.md)
- [K3 内核支持](kernel/README.md)
- [应用集成与 Workspace 交付](docs/deployment/README.md)
- [目标机安装与运行](docs/user/README.md)
- [LLVM、SVF 与外部输入](docs/external-dependencies.md)
- [VLEN 逃逸检测工具](preprocessing/conformance/README.md)
- [v0.1.0-preview.1 发布说明](RELEASE_NOTES-v0.1.0-preview.1.md)

## 仓库结构

| 目录 | 内容 |
|---|---|
| `cli/`、`preprocessing/` | CLI、离线分析、RVV 翻译器、编译器插件与 VLEN 逃逸检测工具 |
| `runtime/` | Runtime、BPF、ABI、启动与工件管理 |
| `kernel/` | K3 内核补丁、配置和构建检查工具 |
| `examples/` | 应用 Profile、构建和运行示例 |
| `docs/` | 用户指南、开发文档、接口和验证记录 |
| `third_party/` | LLVM 与 SVF 子模块源码引用 |
| `tests/`、`tools/` | 回归测试与开发辅助工具 |

## 验证范围

K3 自动迁移的公开验收为**条件性结论**，只覆盖验证记录中固定的硬件、ELF、Profile、依赖和负载；吞吐性能需单独测量。检查通过不代替目标机验证，手动 `migrate` 命令返回 0 也只表示请求提交。详细结论见[发布说明](RELEASE_NOTES-v0.1.0-preview.1.md)及[自动迁移验证](docs/validation/automigration.md)。

## 参与贡献

开发与验证要求见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 版权与许可

ISCAS 对其自研的非内核代码及材料（CLI、离线分析与翻译、编译器集成、Runtime、工具、测试、文档和示例中的自研部分）及 K3 内核补丁贡献保有版权。内核补丁和 BPF 组件保留逐文件许可声明。LLVM、SVF、llama.cpp 子模块，`preprocessing/conformance/svf_src/` 中的 SVF 源码副本，以及 Linux／Spacemit 平台源码等第三方代码，版权归各自原权利人；仓库目录中引入的代码和其他贡献者作品也保留原有声明。完整边界见根目录 [COPYRIGHT](COPYRIGHT)。

版权声明不等于全仓统一授权；各文件与组件按自身许可证分发，不应将整个仓库概括为单一许可证。主要第三方来源见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)，许可证文本与来源边界见 [LICENSES/README.md](LICENSES/README.md)。
