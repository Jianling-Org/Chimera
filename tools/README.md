# 开发与诊断工具

此目录包含 Chimera 源码树的构建入口、回归辅助和开发诊断脚本，不实现运行时功能。用户安装后使用 `chimera-dev`、`chimera-pkg`、`chimera-user`；这些脚本不属于 wheel 的 Python 包映射。源码树中的 `make wheel` 通过 `build_release_wheel.py` 构建发行包。

可重复使用的诊断命令与判据见[开发与诊断指南](../doc/developer/diagnostics.md)。

## 开发入口

| 工具 | 用途 |
|---|---|
| `run_chimera.py` | 从源码树启动 CLI，映射与 wheel 一致的包布局 |
| `build_release_wheel.py` | 发布 wheel 的构建入口 |
| `audit_module_identity.py` | 核对实际导入模块的位置、环境和摘要 |
| `merge_gate_decision.py` | 合并完整报告的候选名单并核对来源 |
| `write_gate_wrapper.py` | 生成固定决策的 C/C++ 编译 wrapper |
| `unknown_stack_scope_profile.py` | 生成显式条件范围 Profile |
| `bench_parse_memory.py`、`bench_analysis_memory.py` | 独立进程测量解析和分析内存；合成结果不代替实机验收 |

使用前运行相应 Python 工具的 `--help`。决策、Profile、wrapper 和报告应写入本次独立工作目录。

## 专项诊断与实验工具

| 工具组 | 主要用途 |
|---|---|
| `layout_codegen_forensics.py` | 对象、命令、输出和 A/B 结果的绑定分析 |
| `diagnose_layout_metadata_mode.py` | 检查元数据模式及绑定传播路径 |
| `builtin_gate_inputs.py`、`builtin_gate_experiment.py` | 收集并分析隔离 A/B 实验输入 |
| `k3_unknown_stack_scope_evidence.py` | 校验归档构建、ELF 摘要与决策文件的身份关系 |

这些 Python 工具用于源码回归和编译器诊断，不是用户工作流入口。相关算法与身份校验仍由回归测试覆盖；诊断结果不能替代 `chimera-pkg check-elf --strict`。详细判据见[诊断指南](../doc/developer/diagnostics.md)及[安全点分析](../doc/developer/architecture/safepoints/README.md)。
