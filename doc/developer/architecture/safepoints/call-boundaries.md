# 调用边界、来源归因与 gate

局部分析判断调用前是否存在敏感状态；调用闭包判断该状态会进入哪些函数，以及传播在哪些边界失去证据。即使中间函数只包含标量指令，只要祖先的敏感栈对象、动态帧或真实宽度缓存仍活跃，中间函数也不能因此获得安全迁移点。

## 状态、传递与固定点

输入是全程序函数集合、每函数局部栈／帧／宽度 `live_before`、编译器函数指针目标 metadata，以及已经绑定的外部叶目标。主要状态包括继承函数集合、局部 seed 边、首次继承见证、未解析站点、未覆盖外部目标及已闭合外部目标。

分析扫描受支持调用与跨函数尾转移。如果站点的局部状态非空，或其宿主已继承 unsafe 上下文，就解析目标：内部目标加入继承集合；集合新增成员后重新传播，直到不再变化。集合单调增长，递归与调用环通过固定点处理，无须把调用栈展开成无限路径。一个被继承的函数也可以同时拥有自己的局部 seed，两类贡献都必须保留。

继承结果保守覆盖被调函数体，并继续沿其受支持转移传播。`first_cause` 给出一条可读的首次见证，`seed_edges` 保留本地源头证据；见证路径不能代替全部贡献者。PLT 跳板不作为内部节点或 gate 源头。普通返回与函数内跳转不作为外部调用；跳到独立函数体的受支持条件转移也参与边界判断。

例如：

```asm
source:
    vs1r.v v8,(sp)
    jal    ra,middle     # 栈对象在此活跃，形成局部 seed
    vl1re8.v v8,(sp)
middle:
    jal    ra,external  # 继承 source 的状态，外部体不在图内
```

`middle` 的 finding 必须追溯 `source`。仅对 `middle` 禁止隐式向量化无法消除祖先对象。源头可能不止一个：多个局部源头汇入同一外部边界时，审计必须保留各贡献者。

## 目标解析与 finding

直接单目标使用 CFG 的目标；其他站点读取 `.chimera.function_pointer`。缺记录无法解析，空记录不可用。目标既可能是内部函数，也可能是 PLT 或其他图外地址，不能只取内部子集后宣称解析完成。

| 活跃站点的目标 | 行为 |
|---|---|
| 完整内部目标 | 加入调用闭包；内部传播本身不产生外部 finding |
| 未解析或空目标集 | `unresolved-active-indirect-call`；空集另保留诊断 |
| 已知 PLT／外部目标，尚无受支持证明 | `active-external-call` |
| 内部与外部目标混合 | 同时保留内部传播和未覆盖外部 finding |
| 标准 ABI 调用的某个外部目标已绑定叶证明 | 仅闭合这个目标；剩余目标继续检查 |
| 没有局部或继承活动 | 不因调用名称或外部性质新增该类 finding |

已知外部地址仍可能调用应用 callback，但当前调用图没有这段边，所以“目标地址已知”不等于传播闭合。`--strategy auto` 遇到活跃的已知外部边界会选择 gate；显式 `--strategy svf` 不能靠补齐地址解决这个缺口，会要求改用 gate 并复检。栈对象覆盖 metadata 与调用目标 metadata 是独立能力。

分析层的 `AnalysisWarning` 结构同时承载可行动边界信息与普通观察，正式检查报告再区分 finding 和 warning。宽度选择影响、已确认非栈写出以及 `escaping-vlen-scalar-value` 观察不单独构成 finding；它们也不自动进入 gate 名单。unsafe、warning、finding、候选名单四者含义不同。

## 局部缓存死亡不解除继承上下文

标准调用按 ABI 结束 caller-volatile 本地缓存；完整的内部 ABI 转移在出口处也不会人为读取全部死缓存，详见[标量宽度缓存](scalar-width.md)。这些是当前函数内的值生命周期规则。

如果 s4 或私有槽在正常调用之后仍有真实读取，调用点依旧有局部 seed；闭包把被调函数及其后代标为 unsafe，不要求额外证明被调函数的寄存器效果。若宿主本就因祖先状态而被继承，即使宿主自己的缓存已经死亡，继承状态仍保留。不得借局部生命周期精化删除祖先证据。

## 从 finding 回到原始源头

gate 决策的目标是消除能够通过禁止隐式向量化移除的源头，而非把全部报错宿主列入名单。来源审计关联 `activity_origins`、分配／恢复地址、证明缺口和调用见证，区分：

- 本地向量栈对象、已知 VLEN 帧、相关保守及不可归约源头。
- 实际仍活跃的 `scalar-width-cache` 本地来源。
- 纯继承宿主，应继续追溯祖先 seed。
- 仅未知标量尺寸，应保留 `trace-size-source` 与待证明分类；UNKNOWN 本身不证明 gate 能消除它。

独立审计使用同一目标分类，对活跃外部边界和未解析站点分别计数；`affected_sites` 保存 `resolution`、`internal_targets`、`external_targets` 及来源贡献者，并与生产闭包交叉核对。选择了 `assume-scalar-independent` 时，报告仍保留该条件范围，不能把排除项改写成已证明独立。

## 名单生成、重编与严格复检

应用集成者用本次 Profile、原 ELF 和独立输出目录生成决策与编译入口：

```bash
chimera-pkg check-elf --profile "$PROFILE" --strategy gate --input "$ELF" \
  --json "$OUT/boundary.check.json" \
  --inheritance-report "$OUT/boundary.inheritance.json" \
  --rebuild-stage gate --rebuild-dir "$OUT/gate"
```

随后把 `$OUT/gate/cc` 和 `$OUT/gate/cxx` 接入应用自己的新构建目录，重编应用，再检查实际将发布的新 ELF：

```bash
chimera-pkg check-elf --strict --profile "$PROFILE" --strategy gate --input "$NEW_ELF" \
  --json "$OUT/final.check.json" \
  --inheritance-report "$OUT/final.inheritance.json"
```

名单生成、编译成功和 census 中的 `blocked` 都不能解除 finding。必须实际完成所有要求的检查，得到 `passed=true` 且 findings 为 0；相同 Profile 的条件范围仍然有效。源码 intrinsic、内联汇编和其他仍存在的向量状态不能被假定已随 gate 消失。检查凭证绑定规则版本；规则升级后须重新检查。

## 内容绑定的外部标量叶证明

当外部目标可以证明只执行受支持的标量叶代码、不会调用应用 callback 时，可闭合该特定外部边界。能力默认关闭，没有按 `memset` 等函数名的内置豁免。安全步骤的 `external_scalar_leaf_contracts` 每项要求精确 `symbol`、scalar 库文件名 `library` 与 64 个小写十六进制字符的 SHA-256 `sha256`；配置是一项证明请求，不是调用者自签的豁免。

验证使用与 prepare 相同的依赖收集和 scalar 选择结果，逐项检查：

1. 原模块是受支持的 RV64 小端 ELF，标准 PLT 机器码、GOT 与 `R_RISCV_JUMP_SLOT` 重定位一致，不依赖反汇编打印名称。
2. 所选模块中恰好存在一个允许的可见定义，属于声明的 scalar 库，内容哈希及符号版本匹配。IFUNC、隐藏版本、绝对符号和未支持绑定保留拒绝原因。
3. 完整符号范围的反汇编连续覆盖原机器码，范围最多 4096 字节；反汇编进程限时 30 秒、输出上限 131072 字节。未覆盖字节不能因为不可达而忽略。
4. 指令属于实现的标量白名单，直接分支留在符号范围内且到达指令边界，存在正常返回。调用、间接跳转、向量、CSR、系统指令及触及受保护状态的操作不构成证明；范围末尾不能落穿。

这套外部叶证明与 `OriginProver` 的内部叶效果摘要不同：它闭合调用边界，不证明任意返回值或内存写可用于尺寸独立性分析。契约适用范围限于标准 ABI 调用，尾调用和非标准链接调用不属于受支持用法。多目标调用只移除已证明的外部目标，其余外部目标与内部传播继续保留。

prepare 对当次选用模块重新绑定并分析，生成 `external-scalar-leaf-contracts` JSON 工件；不能用缓存 safety 结果代替本次绑定。register 与 run 复核实际模块、Runtime、翻译等 ELF 工件，检查同名定义抢占、库内容变更、额外 preload／audit 和 ELF 审计／过滤钩子。即使跳过一般 verify，这项绑定验证仍会执行；启用该契约的启动使用 `LD_BIND_NOW=1` 固定普通 GOT 绑定。

报告把 `external_scalar_leaves` 的证明与拒绝、`closed_external_calls` 和剩余活跃边界分开列出。**closed 仅表示特定传播缺口已闭合，调用者的向量寄存器、栈对象、帧和缓存仍按活跃性分类。** 这也不把库函数内部声明成安全点，不代替运行时寄存器保存、翻译态续点或迁移数值验证。

## 源码与回归

闭包与目标解析见 [liveness.py](../../../../preprocessing/offline/analysis/safety/stack_liveness/liveness.py)；finding 与凭证见 [check_elf.py](../../../../cli/chimera/check_elf.py)，贡献者审计见 [gate_source_audit.py](../../../../cli/chimera/gate_source_audit.py)。外部叶的[代码验证](../../../../preprocessing/offline/analysis/safety/external_leaf.py)、[ELF 绑定](../../../../preprocessing/offline/analysis/safety/external_leaf_binding.py)和[启动复核](../../../../runtime/launcher/run/chimera/launcher/external_leaf.py)共同建立契约。

关键回归是[继承见证](../../../../tests/test_inheritance_trace.py)、[外部调用 gate](../../../../tests/test_external_call_gate.py)、[源头审计](../../../../tests/test_gate_source_audit.py)、[外部叶证明](../../../../tests/test_external_scalar_leaf.py)、[prepare 重绑定](../../../../tests/test_external_leaf_prepare.py)和[启动验证](../../../../tests/test_external_leaf_launch.py)。返回[安全点总览](README.md)。
