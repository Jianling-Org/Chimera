# 第三方软件与来源说明

仓库按文件和组件保留许可证，并在 [LICENSES/README.md](LICENSES/README.md) 解释许可证文本及来源边界。下表汇总子目录中明确引用或包含的第三方源码和内核基线，不额外列入仅由根目录包配置声明的依赖。实际子模块版本和内核基线以仓库中的 gitlink、`SOURCE-VERSIONS.json` 与 `kernel/` 文档为准；本表不是任一 wheel、内核镜像或 Workspace 的完整软件物料清单。

| 组件 | 仓库中的用途与来源 | 许可边界 |
|---|---|---|
| LLVM | `third_party/llvm` 子模块；涧灵的 LLVM 插件与补丁在 `preprocessing/offline/toolchain/` | 上游 LLVM 为 Apache-2.0 WITH LLVM-exception；具体文件及嵌入组件可能另有声明，见[上游仓库](https://github.com/llvm/llvm-project)中的许可文件 |
| SVF | `third_party/SVF` 子模块供 FunctionPointer 元数据路线使用；`preprocessing/conformance/svf_src/` 另含用于 VLEN 逃逸分析、带 RVV 补丁的 SVF 源码副本 | SVF 主体为 AGPL-3.0-or-later；源码副本中的 FastCluster、cJSON、LLVM SparseBitVector 等文件另有版权和许可声明。见[上游许可文件](https://github.com/SVF-tools/SVF/blob/master/LICENSE.TXT)及各文件声明 |
| llama.cpp | `examples/applications/llama-cpp/llama.cpp` 子模块；仓库还提供 RVV 兼容补丁 | 上游许可为 MIT，见[上游仓库](https://github.com/ggml-org/llama.cpp)中的许可文件；模型不随源码提供 |
| Spacemit K3 Linux | `kernel/patches/series` 中的内核补丁依赖 Linux 6.18.3 的 Spacemit 平台源码基线；具体来源和匹配要求见 `kernel/README.md` | Linux 与新增/修改文件的许可证按各自文件头及内核 `COPYING` 执行；GPL-2.0-only 和 Linux syscall exception 文本随仓库提供。补丁作者及原版权声明保留 |

`kernel/patches/` 包含内核补丁正文，不代表仓库包含已构建的内核源码或镜像。根目录 [COPYRIGHT](COPYRIGHT) 同时说明 ISCAS 自研非内核部分、内核补丁贡献和第三方代码的版权边界。内核补丁以 Linux 内核的 GPL-2.0 许可框架及适用的逐文件声明为准，不应对所有补丁文件作单一许可断言。这些声明不替代内核或其他第三方代码原有作者、版权或许可证。Runtime 中的 BPF trigger 也保留其 GPL-2.0-only 文件声明。

LLVM、SVF 和 llama.cpp 的子模块以 gitlink 记录来源，克隆后需按需初始化；但 `preprocessing/conformance/svf_src/` 是仓库内直接收录的源码副本，普通源码检出即包含它，不能按未初始化子模块处理。源码检出和 Python wheel 的实际载荷仍可能不同。模型、scalar 运行库、GCC 源码和构建产物由使用者按各自文档准备。再分发时请核对对应发布物实际包含的文件、子模块内容、补丁、许可证文本和版权声明。
