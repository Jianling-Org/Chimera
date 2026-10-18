# 开发与诊断工具

正式用户流程使用 `chimera-dev`、`chimera-pkg`、`chimera-user`。此目录用于源码开发、性能回归、决策合并及诊断，不是产品准入的另一条路径。

## 持续维护的开发入口

| 工具 | 用途 |
|---|---|
| `run_chimera.py` | 从源码树启动 CLI，映射与 wheel 一致的包布局 |
| `build_release_wheel.py` | 发布 wheel 的构建入口 |
| `audit_module_identity.py` | 比较实际导入模块与源码身份，拒绝 venv 外路径和哈希不一致 |
| `merge_gate_decision.py` | 合并当前完整报告的候选名单，另提供覆盖/局部源头核验 |
| `write_gate_wrapper.py` | 生成固定决策的 C/C++ 编译 wrapper，透传原参数 |
| `unknown_stack_scope_profile.py` | 生成显式条件范围 profile，原 profile 保持不变 |
| `bench_parse_memory.py`、`bench_analysis_memory.py` | 独立进程测量解析和分析内存；合成结果不代替实机验收 |

使用前运行相应 Python 工具的 `--help`。决策、profile 和 wrapper 应写入新的工作目录。

## 保留的诊断工具及回归辅助

| 工具组 | 保留原因与入口 |
|---|---|
| `k3-gate-source-audit.sh` | 原名单与来源证据的独立复核；见[源头审计](../docs/developer/gate-source-audit.md) |
| `layout_codegen_forensics.py`、`k3-forensics-layout-codegen.sh`、`k3-gate-experiment.sh` | 经过回归测试的对象/命令绑定、输出隔离和 A/B 对比；见[编译取证](../docs/developer/analysis-state-memory.md) |
| `k3-forensics-layout-metadata.sh`、`diagnose_layout_metadata_mode.py`、`k3-record-exit-status.sh` | 元数据模式、绑定传播路径及有界内存取证；算法有正反例测试 |
| `builtin_gate_inputs.py`、`builtin_gate_experiment.py` 及两个 builtin Shell 驱动 | 已核对编译单元的隔离 A/B，不能把 census 或脚本退出码当安全通过；见[实验说明](../docs/deployment/gate-build.md) |
| `k3_unknown_stack_scope_evidence.py` | 历史 ELF/决策哈希核对，仍被 builtin 输入收集器使用 |
| `k3-fetch-origin-targets.sh` | 从报告导出待补充的函数体，不重新执行完整分析 |

K3 驱动从脚本位置定位当前源码仓库；Python 环境由 `VENV` 或已激活的 `VIRTUAL_ENV` 指定。工具链默认位于当前用户的 `~/.chimera/toolchain_build`，可用各脚本参数覆盖。

运行前显式选择本次输入：

| 入口 | 必需输入 |
|---|---|
| `k3-gate-source-audit.sh` | `RUN`、`GATE_DECISION`、`EXPECTED_GATE_COUNT` |
| `k3-gate-experiment.sh`、两个 layout 取证驱动 | `RUN` 及脚本声明的报告/决策参数 |
| `k3-collect-builtin-gate-inputs.sh` | `RUN`、`ORIGIN`（构建检查报告目录） |
| `k3-builtin-gate-experiment.sh` | `RUN`、`COLLECTION`（已收集输入清单） |

驱动在缺少必需输入时退出，避免自动选择旧机器或旧实验目录。Python 实现与 fixture 用于对象关联、重定位、CFG、未知目标和证据绑定的回归测试。

## 历史现场材料

诊断脚本的输入、输出和工具路径应显式指定；按本页与正式 docs 选择操作入口。
