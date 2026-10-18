# 开发者命令参考

`chimera-dev` 提供 `rebuild`、`toolchain`、`wheel` 三类命令。通用选项 `--version` 显示版本，`--debug` 放在子命令前，启用离线监测和运行时诊断。

```text
chimera-dev [--debug] rebuild --profile PROFILE --input ELF --workspace ID_OR_PATH
    [--workspace-root DIRECTORY] --steps STEP[,STEP...]
chimera-dev [--debug] toolchain build patched-llvm|llvm-plugin|svf [OPTIONS]
chimera-dev toolchain clean patched-llvm|llvm-plugin|svf [OPTIONS]
chimera-dev wheel [--wheel-dir DIRECTORY] [--artifact-root DIRECTORY]
    [--target-os OS] [--target-arch ARCH] [--target-extension EXTENSION] [--scene SCENE]
```

参数中的大写词表示需要替换的值，方括号表示可选项。实际命令不包含方括号。

## 重建开发工件

`rebuild` 使用明确的开发测试 Profile，在已有开发 Workspace 上重建指定步骤、受影响下游及要求重跑的步骤。步骤选择使用逗号分隔的步骤名或工作流中的精确步骤标识。

```bash
chimera-dev --debug rebuild --profile ./test-profile.toml --input ./app \
    --workspace ./workspaces/app --steps safety
```

解析器允许省略 `--input`，目的是在工件不足时给出具体诊断；实际重建仍需要构建机上的输入 ELF。安装后的交付 Workspace 通常没有所需中间结果，不能据此重放完整开发过程。

`prepare-workspace` 不可通过该命令重新执行。重建不会重新定义应用的内容身份；输入变化时，应重新检查并执行应用集成流程。步骤闭包和回放语义见 [离线架构](architecture/offline.md)。

## 工具链构建

| 目标 | 作用 | 主要选项 |
|---|---|---|
| `patched-llvm` | 使用固定 LLVM 版本和 Chimera 补丁构建工具链 | `--llvm-src`、`--full` |
| `svf` | 构建固定版本的 SVF | `--svf-dir` |
| `llvm-plugin` | 构建所选 Chimera 插件 | `--plugins` |

所有构建目标接受 `--toolchain-build DIRECTORY`，指定安装根目录；`--build-root DIRECTORY` 指定独立构建根目录。默认工具链安装在 `~/.chimera/toolchain_build`，也可通过 `CHIMERA_TOOLCHAIN_BUILD` 设置。

`--plugins` 只适用于 `llvm-plugin`，可选 `stackobject`、`function-pointer`、`vector-gate`，支持一次选择多项。省略时选择全部插件，因此需要完整的 SVF 前置条件。只需 stack-object 与 gate 时显式选择两项：

```bash
chimera-dev toolchain build patched-llvm --llvm-src "$LLVM_SOURCE"
export CHIMERA_LLVM_SRC="$LLVM_SOURCE"
chimera-dev toolchain build llvm-plugin --plugins stackobject vector-gate
```

`--full` 只适用于构建 `patched-llvm`，选择完整 LLVM 构建与安装；默认构建系统所需子集。工具链源目录、固定版本和额外 SVF 路线见 [构建与测试](build-and-test.md)。

## 工具链清理

`toolchain clean` 清理选定目标的构建状态和构建目录。LLVM 清理还会处理补丁应用状态，需指向正确的 LLVM Git 源码目录。对于插件和 SVF，可以提供原构建使用的 `--build-root`。

```bash
chimera-dev toolchain clean llvm-plugin --build-root "$BUILD_ROOT"
```

清理命令用于开发构建恢复。工作树中的个人源码修改应先自行保存，不能把清理当作应用工件安装步骤。

## 系统 wheel

`wheel` 验证并收集已有工具链产物，调用构建后端生成平台 wheel；它不会执行应用的 Profile 或生成应用 Workspace。

| 参数 | 含义 |
|---|---|
| `--wheel-dir` | wheel 输出目录，默认 `dist` |
| `--artifact-root` | 系统发布产物缓存根目录；缺省读取 `CHIMERA_RELEASE_ARTIFACT_ROOT` 或 `~/.chimera/release-artifacts` |
| `--target-os` | 注册目标的操作系统 |
| `--target-arch` | 注册目标的处理器架构 |
| `--target-extension` | 注册目标的架构扩展 |
| `--scene` | 注册的运行场景 |

当前发布示例：

```bash
chimera-dev wheel --wheel-dir dist --target-os linux --target-arch riscv64 \
    --target-extension rvv --scene linux_riscv64_rvv_v1
```

省略目标参数时使用宿主 OS、架构以及默认扩展与场景；只有完整组合已经注册才能发布。构建机与发布目标不同时，应明确指定全部目标参数，并提供实际匹配的目标工具链产物。

缺失或不合法的发布产物会导致命令失败并列出原因；先按 [系统发布指南](releasing.md) 补齐产物。源码构建的等价入口是 `make wheel`。

## 实现入口

- [角色命令解析器](../../cli/chimera/cli.py)
- [工具链构建实现](../../cli/chimera/toolchain.py)
- [系统 wheel 构建器](../../cli/chimera/release_wheel.py)
