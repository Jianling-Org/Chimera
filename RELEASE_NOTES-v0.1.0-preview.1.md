# 涧灵（Jianling）v0.1.0-preview.1 发布说明

这是涧灵的技术预览版；适用环境、验证结果与限制以本文及仓库技术文档为准。

## 本版目标与实现范围

涧灵的长期目标是连接程序兼容与适配、运行状态转换、跨核迁移和调度协同，使 RISC-V 异构核心上的应用能逐步减少针对核心组合的重复适配。当前技术预览实现聚焦 Spacemit K3 上 X100（CPU 0–7，VLEN 256）和 A100（CPU 8–15，VLEN 1024）的 RVV 双向线程自动迁移。

系统离线检查并翻译应用 ELF，生成安全点、翻译代码和 Runtime 工件组成的 Workspace；目标机运行时配合 BPF 触发器和 K3 内核迁移补丁，完成线程状态准备、proposal/ACK 协调、CPU 放置及迁移失败回退。内核补丁只适用于文档指定的 Spacemit 平台源码基线，不可直接套用到任意 Linux 内核。详细边界见[自动迁移状态机](docs/architecture/automigration.md)、[K3 内核说明](kernel/README.md)和[迁移安全边界](docs/security/migration-boundary.md)。

## 主要交付流程

- `chimera-dev`：构建工具链插件和平台 wheel；FunctionPointer 路线所用 LLVM/SVF 由子模块引用提供。
- `chimera-pkg`：根据 Profile 检查 ELF、生成需要的编译重建计划、准备并打包 Workspace。应用主程序不包含在 Workspace 内，目标机需要安装内容匹配的应用及依赖。
- `chimera-user`：校验 Workspace 与运行环境，注册目标机上的应用文件并启动应用。可通过内核策略和 BPF 触发自动迁移，也保留手动迁移请求命令。
- `kernel/`：提供 K3 配套内核补丁系列、冻结配置、源码身份核对和构建脚本；内核需独立获取、构建和部署。
- `preprocessing/conformance/`：提供 VLEN 逃逸分析，检查向量长度值经返回值、堆对象或全局变量传出的情形，并生成 JSONL/Markdown 报告；其 `svf_src/` 是仓库内的 SVF 源码副本，不是子模块。

## 已记录的自动迁移验证

以下结论仅适用于验证记录所述的特定输入与环境。其中"线程"均指应用线程，运行于 K3 的 16 个硬件线程（X100 与 A100 各 8 个）之上。

仓库的[自动迁移验证记录](docs/validation/automigration.md)报告：缩减双向测试 3 轮通过；llama.cpp 应用的线程数矩阵覆盖 2/4/8/12/16/24/32 个应用线程并通过 7 轮；16 线程测试连续 10 轮通过；混合线程负载运行约 2 小时、106 轮通过。记录还报告原生与 123 轮 llama.cpp 测试 PPL 均为 12.7757（预设绝对容差 0.01），并核对成功 COMMIT ACK、逐 TID CPU trace、Runtime 事件及迁移账本清理。

上述为特定测试输入和环境下的**条件性验收结论**，不是对任意 ELF、Profile、依赖、硬件或负载的通用保证，也不是性能承诺。验证依赖条件安全 Profile、`assume-scalar-independent` 范围假设、绑定 libc 身份的 `memset` scalar-leaf 契约、`min_vlen256` 及指定 llama.cpp ELF/模型/语料。变更任一输入组合都需要重新检查和验证。结果摘要及产物身份见 `docs/validation/automigration.json` 和 `docs/validation/measured-artifacts.json`。

## 已知限制与操作边界

- 非零 `vstart` 的向量状态当前不能进入翻译路径；Runtime 会拒绝准备并保留源 signal frame，使线程回到源执行位置继续运行。不得清零 `vstart` 或绕过检查来强制迁移。
- 自动迁移的最终结果需以成功 COMMIT ACK、内核完成计数、正确 translated 路线及其后安全退出到 original 状态共同确认。观察到 proposal 或预提交 PC 改写意图不等于迁移成功。
- `chimera-user migrate` 是手动提交请求的接口；命令返回 0 只说明请求已提交，不等价于自动状态机的完成 ACK。
- GCC 示例中 `xgcc` 流程可执行；`cc1` 整体 prepare 仍有 OOM 阻塞。文档给出的 12 GiB systemd 限制用于限制故障影响，不表示该任务可在此内存下完成。
- llama.cpp 的基础样例关闭 OpenMP、运行单线程 perplexity；多线程迁移验收请看固定的 `reference-v32` 示例和验证记录。不同示例用途不能互相替代。
- 吞吐性能、其他应用及未列出的硬件组合未由当前验收记录覆盖。
- 上述自动迁移验证数据不用于评价 VLEN 逃逸分析；其用法和验证方式见[工具文档](preprocessing/conformance/README.md)。

## 许可证与版权

仓库根目录 [COPYRIGHT](COPYRIGHT) 说明 ISCAS 自研非内核代码及材料、K3 内核补丁贡献与第三方代码各自的版权边界。LLVM、SVF、llama.cpp、仓库内的 SVF 源码副本和 Linux／Spacemit 平台源码的原权利人声明保留；各文件和组件仍按自身许可证分发，不应把整个仓库描述为统一的 Apache-2.0 项目。许可证索引见 [LICENSES/README.md](LICENSES/README.md)；[第三方软件说明](THIRD_PARTY_NOTICES.md)列出主要外部来源。
