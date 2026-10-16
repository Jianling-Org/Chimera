# Chimera 系统发布

系统发布交付可安装的 Chimera wheel。应用 Profile、应用 ELF、模型以及具体 Workspace 由应用集成者管理，见 [集成指南](../integration/README.md)。

## 准备发布输入

在 [构建与测试](build-and-test.md) 所述环境中完成工具链与所选目标验证。发布器使用已有工具链产物；缺少产物时先按[外部依赖说明](../external-dependencies.md#llvm-与-svf)准备源码并构建，发布器不会自动编译 LLVM 或应用。

当前必需输入是：

| 安装前缀中的文件 | 作用 |
|---|---|
| `llvm/bin/clang`、`llvm/bin/clang++` | patched LLVM 的 C/C++ 编译入口 |
| `plugins/lib/chimera/llvm/ChimeraStackObject.so` | 栈对象插件 |
| `plugins/lib/chimera/llvm/ChimeraVectorGate.so` | 向量 gate 插件 |

发布器还会从 LLVM 安装中选择链接器与编译器资源，并处理内部工具别名。普通工具链根目录、单独的 LLVM/插件安装前缀，以及包含 `toolchain/` 的发布缓存都可以作为发现源；使用实际匹配目标平台的产物。

默认工具链根目录为 `~/.chimera/toolchain_build`，可由 `CHIMERA_TOOLCHAIN_BUILD` 指定。发布产物缓存根目录由 `--artifact-root`、`CHIMERA_RELEASE_ARTIFACT_ROOT` 或默认 `~/.chimera/release-artifacts` 选择。

```bash
export CHIMERA_LLVM_SRC="$LLVM_SOURCE"
chimera-dev toolchain build patched-llvm --llvm-src "$LLVM_SOURCE"
chimera-dev toolchain build llvm-plugin --plugins stackobject vector-gate
```

## 生成平台 wheel

当前可用目标的发布命令为：

```bash
chimera-dev wheel --wheel-dir dist --target-os linux --target-arch riscv64 \
    --target-extension rvv --scene linux_riscv64_rvv_v1
```

从尚未安装 CLI 的源码树发布时使用：

```bash
make wheel TARGET_OS=linux TARGET_ARCH=riscv64 TARGET_EXTENSION=rvv \
    SCENE=linux_riscv64_rvv_v1
```

两者最终调用同一个发布构建器。目标组合必须已经在目标目录中注册；仅修改目标参数不能生成新的平台实现。

发布器首先验证发布缓存。缓存不完整时从现有工具链目录收集文件，再检查必需产物。随后生成发布目标配置、创建独立打包暂存目录，并调用 Python 构建后端生成 wheel。缺失文件、越界链接、非法工具别名或未支持目标会明确失败。

## 发布载荷

| 包含 | 说明 |
|---|---|
| 系统 Python 模块 | CLI、离线分析与翻译、工件及在线辅助模块 |
| Runtime 源码与构建资源 | 为选定场景准备运行时所需资源 |
| 编译器、链接器和编译器资源 | 从已有 LLVM 安装中选出的发布子集 |
| StackObject 与 VectorGate 插件 | 当前发布构建器要求的两项插件 |
| 发布目标配置 | 记录本次选择的目标与场景 |

发布载荷不包含应用 Workspace、应用二进制、模型、第三方源码、工具链工程源码或完整 LLVM 开发工具。构建器检查并排除 `llvm-objdump`、`opt`、`llc`、`llvm-tblgen` 和顶层 LLVM 开发静态库等内容。

wheel 包含本地 ELF 资源，因此使用平台标签；发布器同步更新 wheel 元数据和记录摘要。仅凭 Python 模块可导入，不能判断工具链 ELF 是否适用于运行机器。

## 安装与交付验证

在目标平台的独立 Python 环境中，安装本轮产生的准确 wheel 路径：

```bash
python3 -m pip install "$WHEEL_FILE"
chimera-dev --version
chimera-pkg --help
chimera-user --help
```

安装后无需执行初始化命令。验证命令入口和所需的目标工具，再用本轮匹配的 Profile 与应用完成检查、准备、安装及运行验证。运行机器的内核控制接口和 BPF 条件需要另行满足，不能通过 wheel 标签替代。

交付时保留 wheel 的文件名与摘要、源码版本、工具链版本、目标/scene 组合及实际验证结果。应用集成者依据这些能力说明准备应用工件；应用使用者消费另外交付的 `.workspace` 包。

## 实现入口

- [系统发布构建器](../../cli/chimera/release_wheel.py)
- [产物发现与验证](../../cli/chimera/release.py)
- [包安装定义](../../runtime/CMakeLists.txt)

