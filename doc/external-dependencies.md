# 工具链源码准备

构建 Chimera 工具链需要单独准备 LLVM 上游源码；只有 FunctionPointer 元数据路线需要 SVF。Chimera 维护的 LLVM 插件和补丁位于 `preprocessing/offline/toolchain/llvm-21.1.0/`。

## LLVM 与 SVF

Chimera 维护的插件和补丁位于 `preprocessing/offline/toolchain/llvm-21.1.0/`；LLVM 与 SVF 源码需单独获取。固定版本如下：

| 依赖 | 上游仓库 | 固定版本 |
|---|---|---|
| LLVM | [llvm/llvm-project](https://github.com/llvm/llvm-project) | `llvmorg-21.1.0`，提交 `3623fe661ae35c6c80ac221f14d85be76aa870f1` |
| SVF（可选） | [SVF-tools/SVF](https://github.com/SVF-tools/SVF) | `SVF-3.3`，提交 `5c45081f75d16afffc5fc9121e1f2f7a614e0bef` |

例如在源码根目录准备 LLVM：

```bash
mkdir -p third_party
git clone --branch llvmorg-21.1.0 https://github.com/llvm/llvm-project.git third_party/llvm
git -C third_party/llvm checkout --detach 3623fe661ae35c6c80ac221f14d85be76aa870f1
export CHIMERA_LLVM_SRC="$PWD/third_party/llvm"
export CHIMERA_TOOLCHAIN_SOURCE_ROOT="$PWD/preprocessing/offline/toolchain/llvm-21.1.0"
chimera-dev toolchain build patched-llvm --llvm-src "$CHIMERA_LLVM_SRC"
chimera-dev toolchain build llvm-plugin --plugins stackobject vector-gate
```

只有 FunctionPointer 路线需要 SVF：

```bash
git clone https://github.com/SVF-tools/SVF.git third_party/SVF
git -C third_party/SVF checkout --detach 5c45081f75d16afffc5fc9121e1f2f7a614e0bef
chimera-dev toolchain build svf --svf-dir "$PWD/third_party/SVF"
chimera-dev toolchain build llvm-plugin --plugins stackobject function-pointer vector-gate
```

这些外部源码目录由 `.gitignore` 排除，发布源码不含 `.gitmodules` 或 gitlink。按上面的命令单独克隆并检出依赖；构建前确认源码无本地改动，详细要求见[构建与测试](developer/build-and-test.md)。
