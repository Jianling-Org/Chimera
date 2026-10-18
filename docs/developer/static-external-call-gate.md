# 外部调用边界的静态 gate

安全分析不能只在未解析的函数指针处停止。PLT 或其他已知外部地址虽然有确定目标，但被调函数体不在当前 ELF 的可分析调用图中；库再调用应用 callback 时，祖先的敏感栈状态可能无法继续传播。版本 24 将这类活跃边界纳入 actionable findings，版本 25 增加内容绑定的外部标量叶函数证明。当前版本 **32** 跟踪真实的本地宽度缓存，并把已知宽度条件选择的 CFG 控制区域标为 unsafe；普通访存的地址／mask 选择及已确认非栈写出仍只给 warning。完整内部 ABI 转移不会因无后继就人为保留死缓存；真实 unsafe 传播不要求额外的寄存器效果证明。未解析或外部目标不会因内部子集可分析而放行。

## 按活动来源判断，而不是按 PLT 名称禁用

例如：

```text
A（敏感栈状态活跃） → B（自身只有标量代码） → 外部库 → 应用 callback
```

检查在 B 的外部调用处报告 `active-external-call`，保留祖先来源和继承见证；gate 候选是 A。只对 B 禁止隐式向量化不能消除 A 的栈状态。多个源头汇合时，各本地 seed 宿主都会保留，不仅取一条见证路径上的源头。

| 边界及活动状态 | 行为 |
|---|---|
| 内部可解析目标 | 沿内部调用图继续传播 |
| PLT 或其他已知外部目标，且本地或祖先状态活跃 | `active-external-call`，追溯源头 |
| 正常 ABI 调用，外部目标已通过本节的叶函数证明 | 关闭该目标的外部传播缺口；调用者仍按活跃性标为 unsafe |
| 标准 libc `memcpy`，PLT relocation 与实际 libc provider 均绑定 | 按接口语义关闭应用 callback 边界；不声称 memcpy 实现是标量叶子 |
| 目标无法解析，且状态活跃 | 保留 `unresolved-active-indirect-call` |
| 内部和外部目标混合 | 内部传播与外部 finding 同时保留 |
| 编译器目标集为空，且状态活跃 | 空集诊断及未解析 finding；空集不证明没有外部目标 |
| 没有本地或祖先活动来源 | 不因外部调用而新增 finding |

传播也检查非返回的跨函数跳转，包括尾调用和跳到独立函数体的条件分支。函数内跳转、正常返回不作为外部调用。PLT 跳板不成为内部传播节点，也不成为 gate 源头。

## 决策与复检

`--strategy auto` 遇到活跃的已知外部边界时选择 gate；SVF 即使补齐目标地址，也不能补齐外部库到 callback 的调用边。显式 `--strategy svf` 在这种情况下报错，提示使用 gate 并复检。stack-object 覆盖与 gate 仍是独立的编译能力。

规则复用现有的来源归因和名单生成，不将所有外部调用宿主无条件加入名单：

- 本地向量栈对象、已知 VLEN 帧及相关保守／不可归约源头沿现有规则成为候选。
- 实际仍活跃的本地标量硬件宽度缓存沿同一来源链成为候选；warning 不单独成为来源。规则见[标量宽度活跃性](scalar-vlen-liveness.md)。
- 纯继承 finding 追溯祖先 seed；标量中间函数不替代源头。
- 仅未证明的标量尺寸保持 `trace-size-source` 和 pending proof 分类，不能仅凭 UNKNOWN 宣称 gate 能消除它。
- `assume-scalar-independent` 的条件范围不变；它不能排除已知 VLEN 或向量栈对象来源。

使用应用当前的 Profile、ELF 和新输出目录生成 gate 编译入口：

```bash
chimera-pkg check-elf --profile "$PROFILE" --strategy gate --input "$ELF" \
    --json "$RUN/boundary.check.json" \
    --inheritance-report "$RUN/boundary.inheritance.json" \
    --rebuild-stage gate --rebuild-dir "$RUN/gate"
```

随后用生成的 `$RUN/gate/cc`、`$RUN/gate/cxx` 在新构建目录重新编译应用，再严格检查新 ELF：

```bash
chimera-pkg check-elf --strict --profile "$PROFILE" --strategy gate --input "$NEW_ELF" \
    --json "$RUN/final.check.json" --inheritance-report "$RUN/final.inheritance.json"
```

候选名单、编译成功或 `blocked` census 都不解除 finding。新 ELF 必须实际完成所有要求的检查，`passed=true` 且 findings 为 0。源码 intrinsic、内联汇编或其他仍存在的敏感向量代码不能被假定已消除；边界仍活跃时复检继续失败。

## 内容绑定的标量叶函数

用户写的 RVV intrinsic 可能留下跨外部调用的向量 spill，即使 gate 已禁止编译器隐式向量化。若被调库函数是不会回调的标量叶函数，祖先状态没有继续进入应用 callback 的路径，可以关闭这个特定外部目标。调用者的向量寄存器、栈对象和 VLEN 帧仍然活跃，安全点表继续将它们标为 unsafe，不能提前恢复原生执行。

该能力默认关闭，没有按 `memset` 等名称内置豁免。标准 libc `memcpy` 是单独的接口语义契约：只要调用确实绑定到唯一的 `libc.so.6` 提供者并通过 PLT relocation、符号版本和 Manifest 身份核对，就不把该接口视为应用 callback。其 IFUNC 实现选择和内部 helper 不被误称为应用 callback，也不要求把 IFUNC 机器码当作标量叶子证明。该契约不清除调用者的活跃 unsafe 来源，不对其他 libc／未知函数作名称推断。

除此之外，内容绑定的标量叶函数能力默认关闭，没有按 `memset` 等名称内置豁免。需要在 `safety` 步骤参数中声明精确符号、实际选用的库文件名和其 SHA-256；声明只是证明请求。`memcpy` 由上述自动接口契约处理，不能作为手工标量叶函数合同填写。示例中的哈希必须替换成部署库的完整内容摘要：

```toml
[[profile.workflow.steps]]
step = "safety"
parameters = { min_vlen_bits = 256, compiler_metadata = [], external_scalar_leaf_contracts = [{ symbol = "memset", library = "libc.so.6", sha256 = "<64 位小写 SHA-256>" }] }
```

现有 Profile 的其他参数保持原值，包括未知标量尺寸范围策略。验证器使用 prepare 的依赖收集与 scalar 选择规则，要求：

- RV64 little-endian ELF 的标准 PLT 机器码、GOT 地址及 `R_RISCV_JUMP_SLOT` 重定位一致；不相信反汇编打印的名称。
- 全部所选模块中恰好一个可见定义，来自指定 scalar 库，内容哈希及符号版本匹配；IFUNC、隐藏版本、绝对符号和未支持的绑定保留缺口。
- 对完整符号范围进行有界反汇编，逐条核对机器码字节。仅接受已建模的整数指令、函数内直接分支和正常返回；调用、间接跳转、系统／CSR／向量指令、修改栈或返回寄存器、范围缺失均不构成证明。
- 尾调用和非标准 link 寄存器调用不能使用此证明。多目标调用只有已证明的目标关闭，其他目标及内部传播保留。

prepare 对本次所选模块重新绑定并分析，发布 `external-scalar-leaf-contracts` JSON 工件。使用该工件的 register 和 run 核对所有实际加载模块以及 Runtime、翻译等 ELF 工件，拒绝同名符号抢占、库变更、额外 preload、audit 和 ELF 自带审计／过滤钩子。即使跳过一般 verify，这项绑定校验也执行；启动使用 `LD_BIND_NOW=1` 固定普通 GOT 绑定。缓存的 safety 结果不能代替这次绑定，需重新执行 safety。

这是静态的闭合调用边界证明，不是库函数内的安全点声明，也不证明库函数的任意内存写或返回值可用于尺寸独立性分析。

## 报告与凭证

finding 新增 `diagnostic_code` 与十六进制地址列表 `external_targets`，原有 `kind`、`activity_origins`、动作及继承见证继续表达来源。统计新增 `active_external_calls`，继承报告也列出这些边界地址。

外部边界报告区分 `proofs` 与 `no_callback_interfaces`：前者记录机器码标量叶证明，后者记录标准 libc `memcpy` 接口语义、PLT／版本信息和实际 provider 身份。`closed_external_calls` 计数与剩余活跃外部边界分开。显式叶子请求及 provider 哈希参与检查指纹；接口绑定的实际模块哈希在报告和 Workspace Manifest 中记录并于启动时复核。版本 31 及更早凭证不能用于当前版本 32。报告中的 `closed` 不代表调用者安全。

独立来源审计使用同一目标分类，分别统计活跃外部边界与未解析站点；混合目标仍传播内部候选 ID。`affected_sites` 新增 `resolution`、`internal_targets`、`external_targets`，并保留全部来源贡献者。独立闭包会与生产分析结果交叉核对。

v23 曾在已知外部边界停止而不产生该 finding，其通过凭证不能用于 v24。必须重新检查，不复用旧的通过状态。历史 GCC v23 的现场结论仍绑定当时版本；本规则没有重新验证那些产物。

## 适用范围

这个静态方案关闭的是**应用源头的祖先敏感栈状态跨外部边界后传播中断**。它不证明库自身的向量栈状态安全，也不处理翻译态返回续点、双向符号抢占或迁移时寄存器保存。最终静态检查通过仍不能替代真实迁移及数值正确性验收。

本分支不修改 Runtime C 迁移入口、翻译器或内核，不启用动态 callback guard 或自动迁移协议。Python 启动器负责维持已证明库的绑定条件。有关条件范围见[未知标量栈尺寸策略](unknown-stack-size-scope.md)，名单与编译证据核对见[源头独立审计](gate-source-audit.md)。
