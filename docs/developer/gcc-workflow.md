# GCC 重编、静态检查与后续交付

## 工作流与验收范围

本页说明 xgcc/cc1 的检查、重编及交付流程。静态检查成功、Workspace 准备完成、运行结果正确和实际迁移是分别验证的能力；当前发布的硬件和应用验收范围以配对验收摘要为准。GCC 运行时及 exec 子进程迁移需要单独执行目标机验证。

旧检查凭证不能替代当前版本的严格复验。活跃外部调用边界规则见[外部调用边界的静态 gate](static-external-call-gate.md)，当前条件范围见[未知标量栈尺寸策略](unknown-stack-size-scope.md)。

通过使用显式选择的 `unknown_stack_size_policy="assume-scalar-independent"`。该策略排除未证明的普通标量尺寸，不代表这些尺寸已被证明与 VLEN 无关。默认 `conservative` 策略没有放宽。范围语义、预算失效和凭证约束见[未知标量栈尺寸策略](unknown-stack-size-scope.md)。

## 保留的生产修复

- objdump 输出落盘、流式解析、紧凑整数集合和地址状态映射，减少解析及分析内存；阶段监测沿现有 debug 通道输出。
- stack-object 链接地址直接对应反汇编地址；按函数检查敏感访问覆盖，覆盖不足时整个函数回退到二进制分析，不混用对象编号。
- 自环、标量表达式、寄存器依赖、动态帧作用域及控制依赖修正；不能建立可靠固定点或路径证明时保留未知状态。
- 来源归因读取结构化记录，局部源头及 seed 宿主参与候选名单；继承宿主不替代真正源头。未解析活跃调用仍产生 finding，不通过 residual 放行。
- vector-gate 处理已验证的编译器隐式向量化生成路径，包括 builtin 内存操作的 lowering 路径；候选名单不能证明用户显式向量代码一定被消除。
- 翻译产物的地址映射解析支持 `$` 函数入口。此项属于 Chimera 映射接口，不涉及翻译器内部内存实现。

相关回归用例保留在 `tests/`。真实反汇编 fixture 是生产错误的回归输入，不依赖原 K3 或桌面证据包。

## 在新的构建目录重复流程

为应用选择源树、GCC configure 参数、系统编译器及 profile；每轮记录这些输入与工具链哈希。构建必须使用独立目录，产物保留 `.symtab`，不执行 strip。不要直接执行归档中旧版本和旧机器路径的命令。

1. **系统编译器 baseline**：用系统 GCC/G++ 完成原生构建，核对非 stripped 产物，再检查 baseline。
2. **stack-only 重编**：只启用 stack-object，重新构建并检查；收集当前完整报告与继承诊断。节存在不保证覆盖完整，查看逐函数 `access_mode` 和缺失地址。
3. **生成 gate 决策**：从当前各 ELF 的完整报告生成名单并集，保留 stack-object；核对相对旧名单的变化及对应源头，不凭单条日志认定逐函数 gate 生效。
4. **stack + gate 重编**：新构建目录从头编译，不复用旧 `.o`。记录实际消费的决策、编译器、插件及源文件身份。
5. **严格复检**：顺序检查当前 `xgcc`、`cc1`，避免同时运行两个大型分析进程。实际检查必须执行，所需检查无缺失，`passed=true` 且 `findings=0`；构建退出 0 或非 strict 检查退出 0 均不能代替验收。
6. **prepare 与交付**：静态检查通过后生成安全分类、翻译和映射产物，核对映射缺口、补丁数和 Workspace。随后另行进行运行时验收。

设 `PROFILE`、`XGCC`、`CC1` 为当前绝对路径，`OUT` 为新建结果目录，可用正式 CLI 保存报告。原始构建及 stack-only 阶段允许报告失败；下面的命令用于最终严格验收：

```bash
for name in xgcc cc1; do
    if [ "$name" = xgcc ]; then elf="$XGCC"; else elf="$CC1"; fi
    if /usr/bin/time -v -o "$OUT/$name.time.txt" \
        chimera-pkg --debug check-elf --strict \
        --profile "$PROFILE" --strategy gate --input "$elf" \
        --json "$OUT/$name.check.json" \
        --inheritance-report "$OUT/$name.inheritance.json" \
        > "$OUT/$name.log" 2>&1; then
        rc=0
    else
        rc=$?
    fi
    printf '%s\n' "$rc" > "$OUT/$name.exit.txt"
    if [ "$rc" -ne 0 ]; then break; fi
done
```

失败时仍落盘退出码，并停止后续大型检查。报告失败时先处理真实源头、范围假设、缺失证据和 gate 命中问题；不要以循环追加名字和重编替代分析。

合并决策及生成编译 wrapper 使用保留的工具，参数均来自当前文件：

```bash
python tools/merge_gate_decision.py merge \
    --report "$OUT/xgcc.check.json" --report "$OUT/cc1.check.json" \
    --baseline "$OLD_DECISION" --out "$OUT/next.decision.json" \
    --summary "$OUT/decision-diff.md"
python tools/write_gate_wrapper.py \
    --wrapper-dir "$OUT/wrappers" --pkg "$(command -v chimera-pkg)" \
    --decision "$OUT/next.decision.json" --prefix rebuild
```

Wrapper 的输入决策应固定并保存哈希；GCC 构建参数沿已核对的配置传入，编译与链接动作都经过 wrapper。具体 CLI 契约见[部署命令](../deployment/cli.md)，取证工具边界见[工具目录](../../tools/README.md)。

## 运行时验证

完整 prepare 后继续检查依赖、映射与补丁覆盖、实际执行、数值结果、迁移状态链和交付环境。遇到翻译 OOM 时保存独立日志、资源限制和输入身份，先诊断具体阶段；不以反复重跑或缩短检查替代问题定位。可复用工具、真实 fixture 和回归测试保留在源码中，过程性现场记录留在独立验收归档。
