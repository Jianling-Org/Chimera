# 完整文档目录

本清单覆盖项目已跟踪的Markdown文档。构建用CMakeLists、测试反汇编夹具和应用语料不是说明文档；许可证正文另列于文末。每个技术主题保留一个主要说明，ABI/Profile短页作为导航保留。

从根 README 或文档首页选择任务入口。下表列出指南、接口参考和专项验证说明。

## 项目入口与许可证（3）

| 文档 | 内容 |
|---|---|
| [CONTRIBUTING.md](../CONTRIBUTING.md) | 开发与验证 |
| [LICENSES/README.md](../LICENSES/README.md) | 许可证文本与来源边界 |
| [README.md](../README.md) | Chimera |

## 正式指南与协议（45）

| 文档 | 内容 |
|---|---|
| [docs/INDEX.md](INDEX.md) | 完整文档目录 |
| [docs/README.md](README.md) | Chimera 文档 |
| [docs/abi/README.md](abi/README.md) | 协议与 ABI |
| [docs/architecture/README.md](architecture/README.md) | 架构文档 |
| [docs/architecture/automigration.md](architecture/automigration.md) | 双向自动迁移与失败回退 |
| [docs/deployment/README.md](deployment/README.md) | 应用集成指南 |
| [docs/deployment/cli.md](deployment/cli.md) | 应用集成者 CLI |
| [docs/deployment/end-to-end-rvv.md](deployment/end-to-end-rvv.md) | llama.cpp 与 GCC 的端到端命令（K3） |
| [docs/deployment/gate-build.md](deployment/gate-build.md) | Gate 构建 |
| [docs/deployment/profiles.md](deployment/profiles.md) | 应用 Profile |
| [docs/deployment/workspace.md](deployment/workspace.md) | Workspace 打包与安装 |
| [docs/developer/README.md](developer/README.md) | 开发者指南 |
| [docs/developer/abi/README.md](developer/abi/README.md) | 协议与 ABI |
| [docs/developer/abi/bpf-uprobe.md](developer/abi/bpf-uprobe.md) | BPF 可迁移文件注册接口 |
| [docs/developer/abi/compiler-metadata.md](developer/abi/compiler-metadata.md) | 编译器元数据 |
| [docs/developer/abi/manifest-v2.md](developer/abi/manifest-v2.md) | Workspace 清单（Manifest v2） |
| [docs/developer/abi/offset-map-v1.md](developer/abi/offset-map-v1.md) | 地址映射 ABI v1 |
| [docs/developer/abi/runtime-v1.md](developer/abi/runtime-v1.md) | 运行时 ABI v1 |
| [docs/developer/abi/safety-v1.md](developer/abi/safety-v1.md) | 安全表 ABI v1 |
| [docs/developer/analysis-state-memory.md](developer/analysis-state-memory.md) | 分析状态内存：紧凑逐地址状态 |
| [docs/developer/architecture/README.md](developer/architecture/README.md) | Chimera 架构 |
| [docs/developer/architecture/extensibility.md](developer/architecture/extensibility.md) | 扩展 step、target、scene 与 capability |
| [docs/developer/architecture/offline.md](developer/architecture/offline.md) | 离线流水线与发布事务 |
| [docs/developer/architecture/runtime.md](developer/architecture/runtime.md) | 在线启动、工件加载与迁移 |
| [docs/developer/architecture/safepoints/README.md](developer/architecture/safepoints/README.md) | 安全点分析 |
| [docs/developer/architecture/safepoints/call-boundaries.md](developer/architecture/safepoints/call-boundaries.md) | 调用边界、来源归因与 gate |
| [docs/developer/architecture/safepoints/stack-liveness.md](developer/architecture/safepoints/stack-liveness.md) | 栈对象、动态帧与未知尺寸范围 |
| [docs/developer/architecture/targets/README.md](developer/architecture/targets/README.md) | 目标、场景与通用机制 |
| [docs/developer/architecture/targets/rvv/README.md](developer/architecture/targets/rvv/README.md) | Linux / RISC-V64 / RVV 场景 |
| [docs/developer/architecture/workspace.md](developer/architecture/workspace.md) | Workspace、内容绑定与交付 |
| [docs/developer/build-and-test.md](developer/build-and-test.md) | 构建与测试 |
| [docs/developer/cli.md](developer/cli.md) | 开发者命令参考 |
| [docs/developer/diagnostics.md](developer/diagnostics.md) | 开发与诊断 |
| [docs/developer/gate-source-audit.md](developer/gate-source-audit.md) | 隐式向量化源头独立核对 |
| [docs/developer/gcc-workflow.md](developer/gcc-workflow.md) | GCC 重编、静态检查与后续交付 |
| [docs/developer/releasing.md](developer/releasing.md) | Chimera 系统发布 |
| [docs/developer/scalar-vlen-liveness.md](developer/scalar-vlen-liveness.md) | 标量硬件宽度缓存的活跃性 |
| [docs/developer/static-external-call-gate.md](developer/static-external-call-gate.md) | 外部调用边界的静态 gate |
| [docs/developer/unknown-stack-size-scope.md](developer/unknown-stack-size-scope.md) | Explicit scope for unknown scalar stack sizes |
| [docs/external-dependencies.md](external-dependencies.md) | 外部依赖与源码版本 |
| [docs/profiles/README.md](profiles/README.md) | Profile 配置 |
| [docs/security/migration-boundary.md](security/migration-boundary.md) | 迁移安全边界 |
| [docs/user/README.md](user/README.md) | 在目标机运行应用 |
| [docs/user/cli.md](user/cli.md) | 应用使用者 CLI |
| [docs/validation/automigration.md](validation/automigration.md) | 自动迁移验证 |

## 应用示例（5）

| 文档 | 内容 |
|---|---|
| [examples/applications/gcc/README.md](../examples/applications/gcc/README.md) | GCC 应用适配样例 |
| [examples/applications/hello-world/README.md](../examples/applications/hello-world/README.md) | Hello World 迁移样例 |
| [examples/applications/llama-cpp/README.md](../examples/applications/llama-cpp/README.md) | llama.cpp 应用集成样例 |
| [examples/applications/llama-cpp/reference-v32/README.md](../examples/applications/llama-cpp/reference-v32/README.md) | llama.cpp 双向自动迁移 |
| [examples/applications/omp-kernel-probe/README.md](../examples/applications/omp-kernel-probe/README.md) | OpenMP 算子探针 |

## 配对内核（4）

| 文档 | 内容 |
|---|---|
| [kernel/README.md](../kernel/README.md) | K3 内核支持 |
| [kernel/docs/compatibility/baseline.md](../kernel/docs/compatibility/baseline.md) | 内核源码与接口 |
| [kernel/docs/deployment/build-and-rollback.md](../kernel/docs/deployment/build-and-rollback.md) | 构建、部署与回退 |
| [kernel/tests/README.md](../kernel/tests/README.md) | 内核测试与配对验收 |

## LLVM插件与工具链（4）

| 文档 | 内容 |
|---|---|
| [preprocessing/offline/toolchain/llvm-21.1.0/plugins/docs/README.md](../preprocessing/offline/toolchain/llvm-21.1.0/plugins/docs/README.md) | Chimera LLVM 集成工程 |
| [preprocessing/offline/toolchain/llvm-21.1.0/plugins/docs/architecture.md](../preprocessing/offline/toolchain/llvm-21.1.0/plugins/docs/architecture.md) | Chimera LLVM 集成架构 |
| [preprocessing/offline/toolchain/llvm-21.1.0/plugins/docs/llvm-patches.md](../preprocessing/offline/toolchain/llvm-21.1.0/plugins/docs/llvm-patches.md) | LLVM 21.1.0 Patch Series |
| [preprocessing/offline/toolchain/llvm-21.1.0/plugins/docs/testing.md](../preprocessing/offline/toolchain/llvm-21.1.0/plugins/docs/testing.md) | 测试指南 |

## 译器设计与专项验证（17）

| 文档 | 内容 |
|---|---|
| [preprocessing/translator/rvv_sbt_tool/README.md](../preprocessing/translator/rvv_sbt_tool/README.md) | RISC-V 静态二进制翻译器（SBT） |
| [preprocessing/translator/rvv_sbt_tool/TRANSLATOR_ISSUES.md](../preprocessing/translator/rvv_sbt_tool/TRANSLATOR_ISSUES.md) | 翻译器已知问题 |
| [preprocessing/translator/rvv_sbt_tool/docs/ARCHITECTURE.md](../preprocessing/translator/rvv_sbt_tool/docs/ARCHITECTURE.md) | RISC-V SBT 架构与 RVV 翻译流程 |
| [preprocessing/translator/rvv_sbt_tool/docs/IME_RVV.md](../preprocessing/translator/rvv_sbt_tool/docs/IME_RVV.md) | A100 IME to native RVV |
| [preprocessing/translator/rvv_sbt_tool/docs/README.md](../preprocessing/translator/rvv_sbt_tool/docs/README.md) | RVV SBT 文档入口 |
| [preprocessing/translator/rvv_sbt_tool/docs/STATE_ABI.md](../preprocessing/translator/rvv_sbt_tool/docs/STATE_ABI.md) | `simulated_cpu_state` 状态 ABI |
| [preprocessing/translator/rvv_sbt_tool/docs/SUPPORTED_INSTRUCTIONS.md](../preprocessing/translator/rvv_sbt_tool/docs/SUPPORTED_INSTRUCTIONS.md) | 后端注册能力 |
| [preprocessing/translator/rvv_sbt_tool/tests/README.md](../preprocessing/translator/rvv_sbt_tool/tests/README.md) | `tests/` 说明 |
| [preprocessing/translator/rvv_sbt_tool/verify/README.md](../preprocessing/translator/rvv_sbt_tool/verify/README.md) | 翻译器语义验证说明 |
| [preprocessing/translator/rvv_sbt_tool/verify/ime_q3_gemm/CURRENT_RESULTS.md](../preprocessing/translator/rvv_sbt_tool/verify/ime_q3_gemm/CURRENT_RESULTS.md) | 当前 A100 IME→RVV 实现与验证 |
| [preprocessing/translator/rvv_sbt_tool/verify/ime_q3_gemm/README.md](../preprocessing/translator/rvv_sbt_tool/verify/ime_q3_gemm/README.md) | A100 Q3_K GEMM: native IME, translated RVV, original RVV |
| [preprocessing/translator/rvv_sbt_tool/verify/ime_rvv/README.md](../preprocessing/translator/rvv_sbt_tool/verify/ime_rvv/README.md) | IME execution and full-state verification |
| [preprocessing/translator/rvv_sbt_tool/verify/rvv1024_transition/README.md](../preprocessing/translator/rvv_sbt_tool/verify/rvv1024_transition/README.md) | RVV256→RVV1024 过渡路径语义差分 |
| [preprocessing/translator/rvv_sbt_tool/verify/rvv256_wide/README.md](../preprocessing/translator/rvv_sbt_tool/verify/rvv256_wide/README.md) | RVV256 宽路径目标语义验证 |
| [preprocessing/translator/rvv_sbt_tool/verify/rvv_bidirectional_hotspots/README.md](../preprocessing/translator/rvv_sbt_tool/verify/rvv_bidirectional_hotspots/README.md) | 双向 RVV 辅助热点与全状态回归 |
| [preprocessing/translator/rvv_sbt_tool/verify/rvv_q3_gemm/README.md](../preprocessing/translator/rvv_sbt_tool/verify/rvv_q3_gemm/README.md) | 双向 RVV 主 Q3_K GEMM 验证 |
| [preprocessing/translator/rvv_sbt_tool/verify/rvv_q3_gemm/RESULTS.md](../preprocessing/translator/rvv_sbt_tool/verify/rvv_q3_gemm/RESULTS.md) | 双向 RVV 主 GEMM 已接入优化与验收 |

## BPF接口与诊断（2）

| 文档 | 内容 |
|---|---|
| [runtime/bpf/schemas/README.md](../runtime/bpf/schemas/README.md) | BPF map schema |
| [runtime/bpf/trigger/README.md](../runtime/bpf/trigger/README.md) | 自动迁移 BPF 触发器 |

## 开发工具（1）

| 文档 | 内容 |
|---|---|
| [tools/README.md](../tools/README.md) | 开发与诊断工具 |

## 许可证正文

- [Apache-2.0](../LICENSES/Apache-2.0.txt)
- [GPL-2.0-only](../LICENSES/GPL-2.0-only.txt)
- [Linux-syscall-note](../LICENSES/Linux-syscall-note.txt)

保留这些文本不等于将整个项目重新许可；逐文件声明和第三方来源优先。
