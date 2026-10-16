# 标量硬件宽度缓存

标量宽度分析跟踪仍在使用的本地硬件宽度内容，例如 `vlenb` 的副本、`vset*` 得到的 VL、这些值的纯宽度换算，以及暂存到向量寄存器或私有栈槽的内容。迁移到不同宽度后，仍读取旧副本可能混用不同硬件宽度，因此这些点具有 `live_vlen_scalar_data` 原因。

本分析不跨函数推导任意参数／返回值，也不证明任意向量计算的数值等价。宽度影响执行路径、地址、mask 或普通数据的选择时，保留诊断 warning；这些选择影响不单独构成宽度内容、unsafe、seed 或 finding。

## 输入、状态与求解

输入为函数 CFG、目标 `scalar_width_facts`、前后标量表达式、RVV 配置、栈访问事实，以及全程序已确认的内部 ABI 转移站点集合。缺少必需语义能力是错误，不能解释为“没有宽度来源”。

前向状态分别记录实际内容和选择影响：标量寄存器集合、向量寄存器集合、固定帧字节集合、符号区间槽，以及相应的选择集合和未闭合效果 `escaped`。前向汇合使用可能性并集，迭代传播来源；后向根据实际 use/def 求活跃性固定点。输出标记取“可能含宽度的内容”与“后续仍需读取”的交集，并保留未闭合效果状态。

```text
有来源且被后续实际读取 → live_vlen_scalar_data
来源已经覆盖或死亡     → 结束相应本地副本
只有选择影响           → 诊断 warning
真实内容的效果无法建模 → 保留具体缺口及保守状态
```

没有任何宽度来源的函数走快速路径，不保留本维度的逐指令来源图或活跃图。前向更新默认预算为 `max(256, 64 × 指令数)`；耗尽时生命周期未被证明，整个函数保留标记并报告预算 warning，而不使用部分结果宣布死亡。

## 什么算实际内容

来源包括非零目标寄存器的 `vsetvli`、`vsetivli`、`vsetvl`，以及已支持形式和数字别名的 `vlenb`、`vl`、`vtype` CSR 读取。目标为 `zero` 不产生标量副本。对受目标最小 VLEN 支持、常量 AVL 不超过最小 VLMAX 的执行结果，可以证明与硬件宽度无关并排除来源；仅能计算某个可选 VTYPE 的容量，并不等于证明目标支持它。

直接复制、整数／浮点位搬运和受支持的纯宽度换算保留来源。普通输入与宽度混合的进度运算不扩展出新的宽度缓存：

```asm
csrr a2,vlenb
srli s4,a2,1       # s4 保存纯宽度换算后的内容
li   a2,0          # 只结束 a2 副本
jal  ra,worker    # 后面仍读取 s4，因此该缓存跨调用活跃
add  t0,s4,zero
```

```asm
vsetvli a4,a0,e32,m1,ta,ma
addw    s3,s3,a4   # 普通进度累计，不把 s3 认作新宽度缓存
ld      s4,0(s3)   # 选址依赖不能证明加载内容就是宽度
```

第一段在调用点保留真实 s4 副本；第二段仍可能引起选择诊断，但不能仅凭依赖链把所有后续数据标成宽度。原 a4 是否仍活跃需要单独看后续实际读取。

## 私有 spill、覆盖与向量中转

实际内容可沿 `a2 → v8 → s4` 流动。覆盖 a2 不会消除 v8 或 s4；每个副本独立终止。向量寄存器组必须完整且有效覆盖，才能清除对应来源。部分 lane、mask、条件写、读改写和组别名不能被当作完整覆盖；显式 `vstart` 存在未证明的重启前缀时，也不能依赖整段覆盖解除来源。

私有 spill 要求证明访问位于当前已分配帧的范围内。仅仅表达式含入口 SP 不足以证明私有。固定槽按字节记录，符号 VLEN 区间复用栈对象和地址表达式；reload 从已知或可能别名的私有槽取回内容。独立的完整覆盖和已证明的帧收回可以结束对应槽：

```asm
addi sp,sp,-64
csrr t0,vlenb
sd   t0,8(sp)      # 当前已分配帧中的私有宽度槽
li   t0,0
jal  ra,worker    # 后续 reload 保留槽的生命期
ld   s4,8(sp)
add  t1,s4,zero
addi sp,sp,64
ret
```

内存写的内容、地址／索引和执行条件分别判断：

| 情况 | 处理 |
|---|---|
| 实际宽度内容写入已证明私有帧 | 接入本地槽生命期 |
| 实际宽度内容写入已证明非栈地址 | `unsupported-nonstack-width-data` warning；不把后续所有点永久钉为 unsafe |
| 只有地址、mask 或条件依赖宽度 | 选择影响 warning |
| 实际宽度内容写出，位置或私有范围无法证明 | 保存地址／范围缺口及保守效果状态 |

`memory_private=false` 只表示私有性未被证明，不能据此推断已确认非栈。普通参数内存 load 不是宽度来源；随 VL 改变的分块长度、步长或地址也不等于写出了持久宽度缓存。

## 调用 ABI 与出口规则

本地生命周期采用标准 ABI。普通 RA 链接调用结束 caller-volatile 整数／浮点和向量寄存器副本；不因某个实参寄存器含宽度就把值传播到被调函数，也不按返回寄存器名字制造新来源。callee-saved 副本及后续仍会 reload 的私有槽继续保留。实际间接目标与 SP 仍是 use。正常返回读取 ra／SP，不隐式读取 `a0/a1/fa0/fa1`。

全程序分析开始时，用生产调用解析器建立“完整内部 ABI 转移”集合。站点必须是受支持的标准调用或非链接尾转移，目标集合非空、完整，全部目标有内部函数体且没有外部／PLT 成员。只有这类站点可以在尾转移或无后继终端处省去人为的全缓存读取。

```asm
csrr s4,vlenb
jal  ra,known_body # 函数末尾，无本地后续读取
```

若 `known_body` 满足上述完整内部条件，残留 s4 不会仅因“尚未覆盖”就成为活跃缓存。该结论不要求先证明被调函数的值效果或不返回属性，也不认证被调函数安全。若在调用后添加 `add t0,s4,zero`，s4 又会真实跨调用活跃，调用点成为 unsafe，并沿[调用闭包](call-boundaries.md)传播。

以下边界仍保守：

| 边界 | 原因 |
|---|---|
| 仅执行单函数分析，没有全程序目标证据 | 无法建立完整内部转移集合 |
| 空目标集、未解析目标、空函数体 | 缺少可用的目标证据 |
| 内部与外部目标混合，或 PLT | 内部子集不能证明整个边界闭合 |
| 自定义 link 寄存器、未知末尾指令、畸形调用伪指令 | 不满足受支持 ABI 转移条件 |

这些开放终端继续保留全缓存出口 use。完整内部间接调用也不会删除真实目标操作数，动态 SP 仍保留；函数内跳转继续走局部 CFG，不成为跨函数生命周期终点。只有分支条件读取宽度属于选择影响时，不能由这个条件制造内容 use。

本地死缓存结束不会清除已继承 unsafe 上下文、向量栈数据或动态帧。反过来，真实 callee-saved／私有槽副本跨内部调用活跃时，闭包照常把被调函数及其后代标为继承 unsafe。这个过程传播上下文，不是传播参数值。

`OriginProver` 的有限内部标量叶效果 API 是独立能力；本缓存分析不请求它，也不受其单块 64 条指令限制约束。调用快照明确使用 `call_effect.status=not-requested`。动态栈尺寸的来源证明仍按自身规则运行。

## 诊断与 gate 的边界

宽度观察进入主检查与继承报告的 `warnings[]`，使用 `severity=warning`、`actionable=false`。兼容编码 `escaping-vlen-scalar-value` 本身不是 finding。实际 unsafe 遇到未解析／未覆盖外部调用边界时，才由边界分析生成 actionable finding；普通 store 或正常返回不是这样的边界。

`activity_origins[].width_evidence` 可以包含 `chimera-width-obligation-v1` 快照，区分当前可能来源、实际活跃寄存器／向量副本、私有字节区间、内容、地址、mask 和控制。`prior_unclosed_effect=true` 表示此前存在效果缺口，不等价于此刻仍有寄存器副本。片段与符号槽展示最多 64 项；表达式展示限制为 64 节点、16 层、512 字符，并保存总量和 `truncated`。诊断截断不改变求解结果，缺字段也不能当作无来源证明。

来源审计仅为实际本地宽度标记建立 `scalar-width-cache` 候选。死来源、选择 warning、普通 store／return 不制造受影响调用边界，兼容字段 `scalar_width_escape` 保持为 0。`assume-scalar-independent` 只限定 UNKNOWN 栈尺寸，不能排除已识别的真实宽度缓存。gate 名单仍须用重编后的 ELF 严格复检；静态检查不能替代实际迁移及数值验证。

检查凭证包含规则版本；规则升级后，应以新规则严格检查应用 ELF，再执行 `prepare` 并验证 Workspace，使安全点表及翻译补丁与检查结果保持一致。安全表 ABI 版本为 1。

## 源码与关键回归

主实现是[宽度数据流](../../../../preprocessing/offline/analysis/safety/stack_liveness/scalar_width.py)、[全程序接线](../../../../preprocessing/offline/analysis/safety/stack_liveness/analyzer.py)和[内部转移资格解析](../../../../preprocessing/offline/analysis/safety/stack_liveness/liveness.py)。

重点阅读[出口生命期回归](../../../../tests/test_scalar_width_exit_liveness.py)：死缓存终止、正常调用后真实读取、私有 spill、真实间接目标／SP、混合目标、自定义链接和继承状态都分别测试。[冻结反汇编出口回归](../../../../tests/test_scalar_width_exit_fixture.py)使用[夹具](../../../../tests/fixtures/llama_width_exit_cache.dump)验证死缓存退出与正常工作路径真实缓存的区分；夹具结果只证明该回归范围。

其余入口包括[本地内容与选择范围](../../../../tests/test_scalar_width_scope.py)、[基础生命期](../../../../tests/test_scalar_width_liveness.py)、[调用效果边界](../../../../tests/test_scalar_width_call_effects.py)和[诊断快照](../../../../tests/test_scalar_width_diagnostics.py)。返回[安全点总览](README.md)。
