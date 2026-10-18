# llama.cpp 双向自动迁移

本示例在 Spacemit K3 上运行启用 OpenMP 的 llama-perplexity，提供 gate 决策、双向 Profile 和动态验证参数。应用源码与依赖的准备方法见 [llama.cpp 应用示例](../README.md)。

## 前提条件

- 已准备包含项目 LLVM 补丁、stack-object 插桩和 VectorGate 插件的工具链。
- 已应用 [RVV1024 与 RVV256 兼容补丁](../patch/README.md)，并按 [gate 决策](gate.decision.json)构建最终 ELF；按函数禁用自动向量化的范围及 LTO 要求见 [Gate 构建](../../../../docs/deployment/gate-build.md)。
- 已准备 TinyLlama Q3_K_S 模型、[仓库语料](../prompt/file.txt)、scalar 底座和应用依赖，来源见[外部依赖说明](../../../../docs/external-dependencies.md)。
- K3 已部署配套内核并初始化 BPF 环境。

此示例启用 OpenMP，用于多线程自动迁移。通用端到端指南中的 OpenMP OFF 单线程配置使用不同的构建选项。

## 配置 Profile

复制 [bidirectional.toml](bidirectional.toml) 到独立运行目录，填写源码、依赖、数据、Workspace 和 BPF pin 路径。模板的两个翻译方向由 workflow 声明；Profile 显示名为 `1024-to-256`。

- 在 `scalar_root` 中提供标量加载器和底座，在 `target-libs` 中提供匹配的目标依赖。
- 按应用 ABI 与目标机解析规则提供 `libomp.so.5`。构建、检查与运行使用同一份库。
- memset scalar-leaf 契约绑定模板中已验证的 libc 内容。使用其他 libc 时，重新核验其标量叶函数条件，再为实际库建立契约；仅替换摘要不能完成该核验。
- BPF pin 指向已初始化且与配套内核绑定的同一 map 对象。触发器加载见 [BPF 触发器](../../../../runtime/bpf/trigger/README.md)。

模板使用 `assume-scalar-independent` 和上述 libc 契约，静态检查结论为 `conditional`。保留 Profile 和完整报告，并随部署说明记录这些条件。

## 检查与准备

在配置好目标工具与依赖的集成环境中，填写实际路径：

```bash
ELF=/absolute/path/to/llama-perplexity
PROFILE=/absolute/path/to/bidirectional.toml
RUN=/absolute/path/to/run-directory

mkdir -p "$RUN"
export CHIMERA_CMAKE_COMMAND_LOG="$RUN/cmake-commands.jsonl"
chimera-pkg check-elf --strict --profile "$PROFILE" --strategy gate --input "$ELF" \
  --json "$RUN/check.json" --inheritance-report "$RUN/inheritance.json"
```

严格检查通过时退出状态为 0，报告写入 `$RUN/check.json`。在同一 shell 中沿用上述变量，生成 Workspace：

```bash
chimera-pkg prepare --profile "$PROFILE" --input "$ELF" \
  --workspace reference-llama-v1 --workspace-root "$RUN/workspaces"
```

`prepare` 成功后在 `$RUN/workspaces/reference-llama-v1` 生成 Manifest 与运行工件，记录与 `$ELF` 绑定的输入身份。`--workspace` 指定名称，`--workspace-root` 指定存放根目录。

模板的 [cmake-runtime-debug](cmake-runtime-debug) 包装器使用 `/usr/bin/cmake`，在 workflow 的 `cmake -S` 配置调用中追加 `-DCHIMERA_DEBUG=ON`，并按环境变量记录参数。配置其绝对路径和可执行权限。`prepare` 使用常规诊断级别；运行时需要状态链日志时使用 `chimera-user --debug run`。

## 在目标机验证与运行

在满足内核和 BPF 条件的 K3 上执行以下命令。设置 `WORKSPACE` 为目标机上的实际目录；在同机准备时为 `$RUN/workspaces/reference-llama-v1`，跨机器交付时先按 [Workspace 打包与安装](../../../../docs/deployment/workspace.md)安装。

```bash
WORKSPACE=/absolute/path/to/installed/reference-llama-v1
ELF=/absolute/path/to/llama-perplexity

chimera-user verify --workspace "$WORKSPACE"
chimera-user register --workspace "$WORKSPACE" --input "$ELF"
chimera-user run --workspace "$WORKSPACE" --input "$ELF" -- \
  -m /absolute/path/to/model.gguf -f /absolute/path/to/file.txt \
  -c 512 -b 512 -ub 128 --chunks 1 --seed 1234 -t 16 -tb 16
```

本节演示一次 16 线程运行；线程矩阵、连续轮次和混合负载按下一节执行。`verify` 校验目标机环境，通过后注册并启动应用。`register` 成功表示实际应用文件已登记到内核，依赖内容在启动时进一步核验。CLI 与导入模块应来自同一安装目录。更多运行设置和迁移命令见[运行指南](../../../../docs/user/README.md)。

## 验证参数

先在自己的环境中建立同输入的原生 PPL 对照。下表记录已测设置与结果；数值检查使用事先声明的绝对容差 0.01。

使用同一 ELF、模型与语料，设置 `-c 512 -b 512 -ub 128 --chunks 1 --seed 1234`，`-t` 与 `-tb` 同步取 2、4、8、12、16、24、32。

| 项目 | 已测设置与结果 |
|---|---|
| 原生对照 | CPU 0–7，16 线程，PPL 12.7757 |
| 预先声明的 PPL 绝对容差 | 0.01 |

主线程和工作线程采用相同迁移条件，状态转换见[双向自动迁移](../../../../docs/architecture/automigration.md)。部署验证包括缩减双向往返、线程矩阵、账本与告警检查、16 线程连续 10 轮，以及至少两小时的混合线程数负载。完整项目和结果见[自动迁移验证](../../../../docs/validation/automigration.md)，实测文件身份见[产物记录](../../../../docs/validation/measured-artifacts.json)。
