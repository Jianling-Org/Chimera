# llama.cpp 应用集成样例

本例使用 `llama-perplexity` 展示应用构建、检查修复、三个迁移场景准备以及模型输入的交付。目标是 Linux / RISC-V64 / RVV；模型结果、迁移成功与性能均需目标机实际验证。

## 源码、补丁与输入

llama.cpp 由仓库 gitlink 固定到 `4fc4ec5541b243957ae5099edb67372f8f3b550e`。按[依赖说明](../../../docs/external-dependencies.md#llamacpp-与模型)初始化子模块，或用 `CHIMERA_EXAMPLE_PACKAGED=1` 和 `CHIMERA_EXAMPLE_SOURCE_DIR` 显式选择同版本独立源码。先准备匹配的 patched LLVM、插件和 scalar 输入。

脚本依次临时应用以下补丁，退出时逆序还原；不要预先手工重复应用，也不要在有 tracked/staged 修改的源码树运行：

1. [Q5 修复](patch/llama-cpp-rvv-vlen1024-q5-fix-4fc4ec554.patch)
2. [VLEN 兼容调整](patch/0001-llama.cpp-rvv-vlen1024-compatible-with-vlen256.patch)

模型不会随发布包提供。请自行准备兼容 GGUF 与提示文本，核对来源、分发许可和内容摘要；文件名不能证明内容完整。有关模型和 scalar 输入见[外部依赖说明](../../../docs/external-dependencies.md#llamacpp-与模型)。

## 依赖与构建入口

需要 Python、CMake、构建工具、Git、目标工具、系统 clang/clang++ 与 lld、匹配的 patched LLVM 和 Chimera 插件、scalar 底座。`CHIMERA_EXAMPLE_PACKAGED=1` 假定 patched LLVM、插件和 scalar 文件已准备好，不会替你构建这些依赖。OpenMP 由脚本探测，应核对最终 libomp 及目标依赖。wheel 提供 clang/lld 和两个插件，不代表 `opt/llc/llvm-objdump` 或完整 SVF 已安装。

先从目标工具链准备真实的 scalar 文件，并放入 `examples/applications/llama-cpp/scalar/`。脚本需要 `ld-linux-riscv64-lp64d.so.1`、`libc.so.6`、`libgcc_s.so.1`、`libgomp.so.1`、`libm.so.6`、`libstdc++.so.6`；不要用目标机的向量库或不匹配的系统库替代。完整构建会从此目录安装文件到 `~/.chimera/scalar`，因此仅手工设置 `config.scalar_root` 不会满足此脚本的输入要求。目录和文件不随发布包提供，准备边界见[scalar 底座说明](../../../docs/external-dependencies.md#scalar-底座)。

在仓库根目录使用外部源码模式时运行：

```bash
CHIMERA_EXAMPLE_PACKAGED=1 \
CHIMERA_EXAMPLE_SOURCE_DIR="$HOME/.chimera/example-source/llama.cpp" \
CHIMERA_LLAMA_JOBS=2 bash examples/scripts/build/build_llamacpp.sh
```

[build_llamacpp.sh](../../scripts/build/build_llamacpp.sh) 与 [_common.sh](../../scripts/build/_common.sh) 是流程入口。普通源码模式校验 gitlink 并准备依赖，外部模式使用显式检出；scalar 输入仍需核对，不能假定所有构建资源都会自动下载。

脚本使用 `BUILD_SHARED_LIBS=OFF`、`LLAMA_BUILD_SHARED_LIBS=OFF`、`GGML_STATIC=ON`、`GGML_SHARED=OFF`，关闭 native 调优、CURL 和 OpenSSL；系统链接依赖仍需检查。产物路径以输出为准，可用 `CHIMERA_EXAMPLE_ARTIFACT_ROOT` 选择产物根。

## 检查与必要重编

主构建对发现面执行当前 Profile 的 `check-elf`。通过则交付该 ELF；发现问题时，必要的 StackObject 元数据阶段后最多执行一轮 gate 重编和复检。脚本根据报告选择路线，遇到其不支持的 FunctionPointer/SVF 路线会明确退出。

修复复检仍有需处理的发现时脚本返回 3，保留报告；不能以“执行到 prepare 前”为成功标准。独立统计入口 [build_llamacpp_stats.sh](../../scripts/build/build_llamacpp_stats.sh) 用于 census/统计，与主交付用途不同，统计值不构成迁移验收。

手动适配构建时，使用 [固定重编计划](../../../docs/deployment/cli.md#固定重编计划)，把 CMake 编译器显式设为计划的 `cc/cxx`，用独立构建目录生成所需对象；对最终 ELF 执行 `check-elf --strict`。不要编辑 JSON 名单来改变报告结论。安全语义及范围选择见 [安全点文档](../../../docs/developer/architecture/safepoints/README.md)。

## 场景与 Workspace

正常主脚本为最终交付面生成三个场景副本，逐份按对应 Profile 检查、准备：

| 场景副本与 Workspace ID | Profile |
| --- | --- |
| `llama-perplexity-1024-to-256` | [1024→256](../../platforms/k3/linux-riscv64-rvv-1024-to-256.toml) |
| `llama-perplexity-256-to-1024` | [256→1024](../../platforms/k3/linux-riscv64-rvv-256-to-1024.toml) |
| `llama-perplexity-bidirectional` | [双向](../../platforms/k3/linux-riscv64-rvv-1024-256-bidirectional.toml) |

交付 ELF 位于脚本产物根的 `main/`，以打印的 `delivery ELF` 和 `scenarios` 为准。脚本为各 Workspace 重建 debug Runtime。场景副本也需按场景检查，复制文件不会复制登记凭据。

交付一个场景并显式包含资源：

```bash
MODEL="/absolute/path/to/tinyllama-1.1b-chat-v1.0.Q3_K_S.gguf"
chimera-pkg workspace pack --workspace llama-perplexity-1024-to-256 \
  --resource "$MODEL=model/tinyllama.gguf" \
  --resource "$PWD/examples/applications/llama-cpp/prompt/file.txt=prompt/file.txt" \
  --output llama-perplexity-1024-to-256.workspace
```

模型也可由目标机独立准备。应用 ELF 不随 `.workspace`，目标机必须安装对应场景的同内容 ELF 和目标解析依赖。安装后资源位于该 Workspace 的 `resources/`。模型需由使用者单独取得，见[模型来源说明](../../../docs/external-dependencies.md#llamacpp-与模型)。

## 显式运行和迁移

在目标机设置 `ELF` 为场景副本路径，`MODEL`、`PROMPT_FILE` 为实际资源路径：

```bash
WORKSPACE=llama-perplexity-1024-to-256
chimera-user verify --workspace "$WORKSPACE"
chimera-user register --workspace "$WORKSPACE" --input "$ELF"
chimera-user --debug run --workspace "$WORKSPACE" --input "$ELF" -- \
  -m "$MODEL" -f "$PROMPT_FILE" > llama-perplexity.log 2>&1 &
PID=$!
```

等 Runtime ready 且所需计算 worker 已创建，按实际 TID 提交：

```bash
chimera-user migrate --workspace "$WORKSPACE" \
  --threads "$WORKER_TID" --direction 1024-to-256
wait "$PID"
```

双向场景返回请求使用 `--direction 256-to-1024`，先确认线程处于相应状态。`--parent-thread "$PID" --migration-count N` 按较大 TID 优先选择非主线程，不识别计算角色，不能仅靠线程总数证明覆盖范围。

[1024→256 运行脚本](../../scripts/run/run_llamacpp_1024_to_256.sh) 等示例显式验证并传递 `--input`。这些手工迁移示例不替代自动调度验收；自动迁移可包含主线程，状态机见[自动迁移说明](../../../docs/architecture/automigration.md)。

## 验证与证据边界

保存最终 ELF、Profile/检查 JSON、包摘要、模型与文本摘要、运行参数、应用结果、线程 TID/核位置和 Runtime 事件。静态检查仅证明当前检查范围；perplexity 需与同模型、输入和参数的参考运行比较；迁移返回 0 只证明提交。正常输出不单独证明全部计算线程迁移，也不能推导其他模型、输入或线程数的性能。

[应用集成者指南](../../../docs/deployment/README.md) · [应用使用者指南](../../../docs/user/README.md)
