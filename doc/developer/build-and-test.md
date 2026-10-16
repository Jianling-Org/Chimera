# 构建与测试

本页说明系统开发环境、离线工具链构建和验证层次。应用的源码构建与资源准备放在各 [应用样例](../README.md#应用样例) 中。

## 开发环境

Python 要求 3.11 及以上，Python 依赖包括 `pyelftools`。源码安装使用 `scikit-build-core` 构建后端；运行时和工具链构建需要 CMake、适用的 C/C++ 编译器，以及构建所需的系统依赖。当前运行目标是 Linux/RISC-V64/RVV，Windows 等开发宿主上的可移植测试不能代替目标运行验证。

从仓库根目录安装开发包：

```bash
python3 -m pip install -e .
```

`make develop` 是同一开发入口。安装不会生成应用 Profile、准备应用 Workspace 或下载模型。

## LLVM 与插件

Chimera 使用 LLVM `llvmorg-21.1.0` 基线及仓库维护的补丁。构建器要求 LLVM Git 源码目录处于可识别、无个人修改的状态，并校验固定基线。已安装的 `bin` 目录不能充当源码目录。

本发布树不含 LLVM/SVF 子模块或其 gitlink。请按[外部依赖准备说明](../external-dependencies.md#llvm-与-svf)准备独立源码检出，并指定路径：

```bash
export LLVM_SOURCE="/absolute/path/to/llvm-project"
export CHIMERA_LLVM_SRC="$LLVM_SOURCE"
export CHIMERA_TOOLCHAIN_SOURCE_ROOT="$PWD/preprocessing/offline/toolchain/llvm-21.1.0"
chimera-dev toolchain build patched-llvm --llvm-src "$LLVM_SOURCE"
chimera-dev toolchain build llvm-plugin --plugins stackobject vector-gate
```

构建器校验源码后应用补丁、构建并安装。补丁状态异常或上次构建中断时，先阅读具体错误，再使用 [工具链清理命令](cli.md#工具链清理) 恢复指定源码与构建状态。

| 插件 | 能力 |
|---|---|
| `stackobject` | 在最终 ELF 中携带栈对象与指令关联信息 |
| `vector-gate` | 按固定函数决策抑制编译器隐式向量化 |
| `function-pointer` | 使用 SVF 提供间接调用目标元数据 |

若需要间接调用元数据路线，额外准备独立 SVF 源码检出。当前构建器固定使用 `SVF-3.3` 对应提交 `5c45081f75d16afffc5fc9121e1f2f7a614e0bef`；源码准备见[外部依赖说明](../external-dependencies.md#llvm-与-svf)：

```bash
chimera-dev toolchain build svf --svf-dir "/absolute/path/to/SVF"
chimera-dev toolchain build llvm-plugin --plugins stackobject function-pointer vector-gate
```

系统发布 wheel 的必需插件为 stack-object 与 gate。需要其他能力时，应单独准备并验证相应依赖和插件，详见 [编译器元数据](abi/compiler-metadata.md)。

## 目录与工具来源

| 设置 | 用途 |
|---|---|
| `CHIMERA_TOOLCHAIN_SOURCE_ROOT` | Chimera 工具链工程目录，包含 `plugins/CMakeLists.txt` 及补丁等资源 |
| `CHIMERA_LLVM_SRC` / `--llvm-src` | LLVM Git 源码目录 |
| `CHIMERA_SVF_DIR` / `--svf-dir` | SVF 源码目录 |
| `CHIMERA_TOOLCHAIN_BUILD` / `--toolchain-build` | 工具链安装根目录，包含 `llvm/`、`svf/`、`plugins/` |
| `CHIMERA_BUILD_ROOT` / `--build-root` | 独立构建目录根位置 |

常规发布 wheel 不包含第三方源码和工具链工程源码。安装包缺少源码资源时，源码构建应使用仓库或显式提供上述路径。发布 wheel 还会裁剪完整 LLVM 安装，不能假定它包含 `llvm-objdump`、`opt` 或所有开发库。离线构建机所需反汇编、符号和目标编译工具应按 [Profile](../integration/profiles.md) 单独准备。

## 选择验证层次

| 层次 | 验证内容 | 运行入口 |
|---|---|---|
| Python 回归 | 命令、配置、算法、协议及交付边界 | `make python-test` |
| 可移植 C 回归 | 与目标硬件无关的运行时决策、映射和状态布局 | `make portable-c-test` |
| 工具链测试 | LLVM 补丁、插件与最终 ELF 元数据 | 工具链源码中的 lit、集成及负例测试 |
| 目标机验证 | RISC-V 汇编与链接、动态装载、BPF、真实信号帧、迁移及应用输出 | 与发布目标匹配的 Linux/RVV 环境 |

也可先运行与改动对应的 Python 测试，例如：

```bash
python3 -m unittest discover -s tests -p 'test_cli_entrypoints.py'
python3 -m unittest discover -s tests -p 'test_safety_classifier.py'
```

可移植 C 测试可显式指定编译器和构建目录：

```bash
cmake -S runtime -B build/runtime-tests -DCHIMERA_BUILD_RUNTIME=OFF \
    -DCHIMERA_INSTALL_RUNTIME_SOURCE=OFF -DCHIMERA_BUILD_TESTS=ON
cmake --build build/runtime-tests --parallel
ctest --test-dir build/runtime-tests --output-on-failure
```

选择与改动相关的测试，再验证受影响的接口组合。算法测试、生成汇编、静态检查、实际运行和迁移后的数值结果分别提供不同证据；发布记录应说明实际执行的环境与检查。

## 源码入口

- [构建入口](../../Makefile)与 [Python 包定义](../../pyproject.toml)
- [工具链构建器](../../cli/chimera/toolchain.py)
- [LLVM 集成工程](../../preprocessing/offline/toolchain/llvm-21.1.0/plugins/CMakeLists.txt)
- [运行时测试](../../runtime/tests)


## 翻译器回归

安装测试依赖 `python3 -m pip install pytest`，从仓库根目录执行 `make translator-test`。`make test` 同时运行系统 Python、翻译器和可移植 C 测试。详见[翻译器使用与开发](../integration/translator.md)。

## 宿主平台与发布范围

`make portable-c-test` 当前包含 Linux 信号结构相关条目。macOS 的 `siginfo_t` 不提供这些条目使用的 `si_ptr`，因此完整 C 测试目标在 macOS 上可能编译失败；不能将其描述为已全部支持跨平台运行。完整信号与迁移验收应在匹配的 Linux/RISC-V 环境执行。

插件测试脚本带有工具链路径默认值。在自己的环境中运行时，应显式覆盖 stackobject 的 `LLVM` 安装根和 vector_gate 的 `CLANG` 可执行文件，选择匹配的已打补丁工具链。

本地 `.venv/`、`build/`、测试缓存与对象文件由 Git 忽略。发布源码归档应使用版本控制的文件清单，不应直接压缩整个开发目录。
