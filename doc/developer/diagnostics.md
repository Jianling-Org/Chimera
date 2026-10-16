# 开发与诊断

本页介绍可重复使用的诊断入口。正式应用准入使用 `chimera-pkg check-elf`，应用运行使用 `chimera-user`。诊断报告解释输入与实现行为，其退出码不能替代安全检查凭证。

## 确认实际导入的代码

源码、虚拟环境与 wheel 可能同时存在。首先确认运行命令的 Python 环境与安装版本；需要逐模块核对时，使用仓库中的模块身份检查器：

```bash
python3 tools/audit_module_identity.py --source-root "$PROJECT_ROOT" \
    --venv "$VENV_ROOT" --out-dir "$DIAG_DIR/module-identity"
```

默认清单覆盖参与安全分析和诊断的模块，也可重复提供 `--module NAME=RELATIVE_PATH`。工具核对实际导入位置、预期虚拟环境和源码摘要，写出导入记录、模块表与结论。它用于核对安装一致性，不改变检查结果或应用文件。

命令从仓库根目录执行；输出目录指向本次独立的诊断目录。实现与参数见 [身份检查器](../../tools/audit_module_identity.py)。

## 取得正式检查报告

```bash
chimera-pkg --debug check-elf --strict --profile "$PROFILE" --input "$ELF" \
    --json "$DIAG_DIR/check.json" --inheritance-report "$DIAG_DIR/inheritance.json"
```

同时保留 ELF 内容摘要、原 Profile、工具版本及这些报告。`--debug` 位于子命令前，会打开阶段、函数和内存监测；监测读取失败不应改变分析语义。普通运行不启用这些监测。

先判断检查是否实际执行、报告是否通过，再定位 finding 的原始来源与调用传播。详细判据见 [安全点算法](architecture/safepoints/README.md) 和 [集成命令参考](../integration/cli.md)。

## 独立核对 gate 源头

源码环境提供独立审计模块，用于核对名单、编译证据和被审 ELF 的来源关系：

```bash
python3 -m chimera.gate_source_audit audit --input "$ELF" \
    --gate-list "$DECISION" --consumed-decision "$DECISION" \
    --expected-gate-count "$EXPECTED_COUNT" --stage "$AUDIT_STAGE" \
    --census "$CENSUS_FILE" --evidence "$EVIDENCE_FILE" \
    --check-report "$DIAG_DIR/check.json" \
    --json "$DIAG_DIR/audit.json" --report "$DIAG_DIR/audit.md"
```

运行前用该模块的 `audit --help` 核对可接受的阶段标识。`EXPECTED_COUNT` 应与所用名单或决策去重后的项数一致；名单规模不同于工具内置基线时，通过 `--expected-gate-count` 显式指定。阶段、证据、决策和 ELF 必须来自同一被审构建。

| 输入 | 需要表达的事实 |
|---|---|
| `--gate-list` | 本次审计对照的原始名单或决策 |
| `--consumed-decision` | 被审构建实际消费的决策，用于证据绑定 |
| `--census` | 编译器逐函数决策记录，可重复提供 |
| `--evidence` | 把编译证据绑定到被审构建身份的清单 |
| `--check-report` | 同一 ELF 的检查报告，作为交叉参照 |

缺少完整绑定证据时，工具应保留“未绑定”或证据不足的结论。报告给出的候选源头不等于已消除源头；重新编译的产物仍需正式严格复检。

跨构建对比使用两份审计 JSON：

```bash
python3 -m chimera.gate_source_audit compare --baseline "$BEFORE_AUDIT" \
    --audited "$AFTER_AUDIT" --json "$DIAG_DIR/compare.json" \
    --report "$DIAG_DIR/compare.md"
```

该接口按符号核对证据变化，不能仅按两个构建中的地址作对应。实现见 [源头核对模块](../../cli/chimera/gate_source_audit.py)。

## 分析内存与阶段进度

合成基准在独立进程中比较解析或安全分析的资源使用与语义摘要：

```bash
python3 tools/bench_parse_memory.py --help
python3 tools/bench_analysis_memory.py --instructions 150000 \
    --json build/bench/analysis-memory.json
```

记录输入规模、运行环境、峰值 RSS、阶段耗时与语义摘要。状态表示的优化需要保持分类与来源语义；合成基准不能代替真实程序的峰值内存、实际迁移和数值对照。

源程序大小、函数数量和单函数状态膨胀可能分别成为瓶颈，使用阶段监测区分解析、配置、局部分析与调用传播。监测实现见 [内存采样](../../preprocessing/offline/analysis/core/monitor/memory.py)。

## 运行时问题

在打开诊断的运行中，结合 Runtime 初始化、源/目标路线、陷阱 PC 和精确映射定位问题。`parent_thread_id` 表示该进程的 Runtime 已初始化，不表示迁移完成。

遇到翻译中的未映射陷阱时，应核对对应翻译 DSO、反向映射与生成汇编。陷阱映射必须指向精确的指令入口，相邻地址不能替代该映射。状态转换和失败语义见 [Runtime 架构](architecture/runtime.md)，目标信号布局见 [RVV 目标实现](architecture/targets/rvv/README.md)。

