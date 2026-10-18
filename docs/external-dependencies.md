# 外部依赖与源码版本

源码目录包含双向 RVV 翻译器，以及 LLVM、SVF 和 llama.cpp 的固定子模块引用；子模块内容需要单独初始化。模型、scalar 底座和编译产物作为外部运行输入准备。下面的下载与构建命令由使用者按需执行，这些步骤独立于 Python 包安装。

## 翻译器

双向实现位于 `preprocessing/translator/rvv_sbt_tool/`。`rvv_sbt_rvv.py` 提供 1024→256，`rvv_sbt_rvv1024.py` 提供 256→1024；Python 包定义包含 `chimera.preprocess.translator`。必须使用与当前 Runtime ABI、状态布局及路线匹配的翻译器；替换入口文件前核对这些条件。

在应用 Profile 中填写真实绝对路径，例如：

```toml
[[config.translators]]
source = "riscv64;rvv;vlen=1024"
target = "riscv64;rvv;vlen=256"
translator_path = "/absolute/path/to/Chimera/preprocessing/translator/rvv_sbt_tool/rvv_sbt_rvv.py"
```

需要反向路线时，再声明对应的 `256-to-1024` 绑定及翻译步骤，入口为 `rvv_sbt_rvv1024.py`。样例中的绝对路径需要替换；文件不存在时配置会拒绝使用，不会静默跳过翻译。协议见 [Runtime ABI](developer/abi/runtime-v1.md)。

## LLVM 与 SVF

保留的 Chimera 插件和补丁位于 `preprocessing/offline/toolchain/llvm-21.1.0/`；上游源码单独取得。固定版本来自本仓库的 gitlink：

| 依赖 | 上游仓库 | 固定版本 |
|---|---|---|
| LLVM | [llvm/llvm-project](https://github.com/llvm/llvm-project) | `llvmorg-21.1.0`，提交 `3623fe661ae35c6c80ac221f14d85be76aa870f1` |
| SVF（可选） | [SVF-tools/SVF](https://github.com/SVF-tools/SVF) | `SVF-3.3`，提交 `5c45081f75d16afffc5fc9121e1f2f7a614e0bef` |

例如在源码根目录准备 LLVM：

```bash
git submodule update --init third_party/llvm
export CHIMERA_LLVM_SRC="$PWD/third_party/llvm"
export CHIMERA_TOOLCHAIN_SOURCE_ROOT="$PWD/preprocessing/offline/toolchain/llvm-21.1.0"
chimera-dev toolchain build patched-llvm --llvm-src "$CHIMERA_LLVM_SRC"
chimera-dev toolchain build llvm-plugin --plugins stackobject vector-gate
```

只有 FunctionPointer 路线需要 SVF：

```bash
git submodule update --init third_party/SVF
chimera-dev toolchain build svf --svf-dir "$PWD/third_party/SVF"
chimera-dev toolchain build llvm-plugin --plugins stackobject function-pointer vector-gate
```

`.gitmodules` 与 gitlink 固定上述来源和提交。也可使用相同提交的独立外部检出，并用工具链参数显式指定。构建前确认源码无个人改动；不要覆盖工具链构建器管理的补丁状态，详细要求见[构建与测试](developer/build-and-test.md)。

## llama.cpp 与模型

llama.cpp 使用 [ggml-org/llama.cpp](https://github.com/ggml-org/llama.cpp) 的 `4fc4ec5541b243957ae5099edb67372f8f3b550e`。项目的 RVV1024 算子与 RVV256 兼容回退由[补丁集](../examples/applications/llama-cpp/patch/README.md)提供。示例脚本按固定顺序临时应用补丁，退出时逆序恢复；自有构建按补丁说明手动集成。初始化官方源码：

```bash
git submodule update --init examples/applications/llama-cpp/llama.cpp
```

样例构建脚本检查子模块身份。使用固定子模块时按样例入口运行；需要现有独立源码时，可显式使用外部源码模式，且先准备好 patched LLVM、插件和 scalar 输入：

```bash
export CHIMERA_EXAMPLE_PACKAGED=1
export CHIMERA_EXAMPLE_SOURCE_DIR=/path/to/llama.cpp
CHIMERA_LLAMA_JOBS=2 bash examples/scripts/build/build_llamacpp.sh
```

运行脚本所需的模型由使用者提供。原样例模型元数据为：

| 项目 | 值 |
|---|---|
| 模型 | `tinyllama-1.1b-chat-v1.0.Q3_K_S.gguf` |
| 上游 | [TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF](https://huggingface.co/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF) |
| 上游版本 | `e14b9934fb66bca914841e9c2ce0ef53c07853cf` |
| 字节数 | `500315520` |
| SHA-256 | `6d58c8fbdaa822b004d7ba473f9b9ad4d1ef7c2dd2c4cf9f9856451aa44bf0ca` |

上表 SHA256 用于校验指定上游版本的下载文件。自行构建的应用、运行库和内核镜像不要求复现项目测试产物的哈希；应检查实际输入、执行 strict 检查并完成目标机运行验证。Workspace 中的摘要用于核对准备和运行阶段是否使用同一文件。

模型元数据实现见 [model.py](../cli/chimera/model.py)。输入文本仍在 [prompt/file.txt](../examples/applications/llama-cpp/prompt/file.txt)。按[样例说明](../examples/applications/llama-cpp/README.md)设置模型路径；保留上游许可及来源信息，模型不会随源码或默认 Workspace 自动交付。

## scalar 底座

`config.scalar_root` 指向使用者单独准备、与目标 ABI 匹配的标量加载器和依赖。scalar 底座需要经过标量实现核验；重命名或复制目标系统库不能完成该核验。

llama.cpp 完整构建脚本会从 `examples/applications/llama-cpp/scalar/` 安装底座。该目录未随本分发提供；执行脚本前需放入经过核验的 `ld-linux-riscv64-lp64d.so.1`、`libc.so.6`、`libgcc_s.so.1`、`libgomp.so.1`、`libm.so.6`、`libstdc++.so.6`。安装器会核对冲突，不覆盖未知来源的已有文件。

实际 OpenMP 运行库（例如 `libomp.so.5`）仍需按应用构建和 Profile 的依赖解析准备，不因这份清单就被当作已有 scalar 库。独立手工集成可直接配置自己的 `scalar_root`，不必使用样例安装器。见 [Profile](deployment/profiles.md) 与 [Workspace](deployment/workspace.md)。
