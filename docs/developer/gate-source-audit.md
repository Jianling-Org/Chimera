# 隐式向量化源头独立核对

`chimera.gate_source_audit` 是对 gate 整改的**独立复核**，不是第二套 gate。它回答两个问题，
并且**只**回答这两个：

1. 在约定的范围内，哪些候选源头**没有**被原 gate 名单覆盖？
2. 原 gate 名单中的函数，哪些仍**有来源**、哪些有**生效证据**、哪些**证据不足**？

它以 `chimera-gate-source-audit-v1` 格式输出 JSON、两份可筛选 CSV 和一份中文结论报告。源码在
[gate_source_audit.py](../../cli/chimera/gate_source_audit.py)，目标机执行脚本在
[k3-gate-source-audit.sh](../../tools/k3-gate-source-audit.sh)。

来源传播同时覆盖活跃的未解析调用和已知外部边界（PLT／Program 外目标）。混合目标集保留内部传播，
不能过滤外部目标后宣称闭包完整。尾调用及跨函数分支也携带祖先来源，正常返回和函数内跳转不作为边界。
`propagation` 分列 `active_unresolved_sites`、`active_external_sites`；`affected_sites` 保留贡献者，
并新增 `resolution`、`internal_targets`、`external_targets`。这些地址属于当前 ELF，不是跨构建身份键。
判定与复检要求见[外部调用边界的静态 gate](static-external-call-gate.md)。

## 职责与退出码

- 不导入 check-elf 的诊断模块，不读也不写检查凭证（`~/.chimera` 下的任何内容）。
- 不修改安全点分类、通过判据、检查版本，也**不把审计结果写回 gate 决策**。
- 读取参数指定的ELF与构建证据，不执行被审应用，也不代替重新编译。
- 退出码 `0` 只表示**审计执行完成**。证据不足照样是 `0`，并在报告里写明。
  "脚本跑成功"永远不等于"安全检查通过"。

## 分析假设与范围

范围是**编译器隐式向量化**引入的向量栈对象、尺寸依赖 VLEN 的栈分配，以及已识别的标量硬件宽度缓存。
判断规则如下，且每一条都会原样写入 JSON 的 `assumptions.statements`：

| 情形 | 处理 | 理由 |
|---|---|---|
| 分配尺寸直接或**已追踪**依赖 VLEN | 保留为源头 | 属于需要 gate 处理的 VLEN 依赖来源 |
| 分配尺寸只是普通 `UNKNOWN` | **按假设排除**，逐项记录，标为"未经证明" | 普通参数、计数、外部返回值都会产生 UNKNOWN，把它当源头会淹没真信号 |
| VLEN 依赖经寄存器搬运、暂存、加载回读 | 保留 | "过了内存"本身不是排除理由 |
| 显式向量代码、来源不明的向量代码 | 单列，不承诺 gate 必然消除 | 无法判断来源的向量代码不能被 any gate 名单保证 |

**排除不等于安全。** 排除项在 JSON 里带 `excluded_by_assumption=True`，在报告里逐条列出。
任何结论都不得把排除项读成"已证明安全"。

标量宽度候选的类型为 `scalar-width-cache`，只由实际本地宽度活跃状态产生，不随 UNKNOWN 尺寸假设排除。版本 30 的选择影响与已确认非栈写出为 warning，不制造候选或受影响边界；普通 store／return 不是调用边界。旧 `scalar_width_escape` 及相关计数字段兼容保留为 false／0。实际活跃的内部调用继续传播，未解析／外部边界保留目标与来源；详见[标量宽度活跃性](scalar-vlen-liveness.md)。

## 运行方式

### 单份 ELF

```text
python -m chimera.gate_source_audit audit \
  --input "$ELF" --gate-list "$DECISION" --stage "$AUDIT_STAGE" \
  --expected-gate-count "$EXPECTED_COUNT" \
  --census TU.census.tsv --evidence 证据清单.json \
  --consumed-decision 该构建消费的决策.json \
  --json out.json --candidates-csv candidates.csv --gate-csv entries.csv --report report.md
```

`--gate-list` 接受两类文件：派生的 `*.gate_names.txt`（每行一个 mangled name，就是插件读的那个）
或它派生自的 decision JSON（取 `decision.gate.names`）。两者都做与插件一致的去重，并回报原始行数、
非空行数、去重后项数和被丢弃的重复行数。它是**对照名单**，见下节。
`--consumed-decision` 是**被审构建自己消费的决策**，用于 census 证据绑定（见"决策身份"一节）；
两个角色分开打印。

### 跨构建对比

```text
python -m chimera.gate_source_audit compare --baseline 建仓审计.json --audited gate2审计.json \
  --json compare.json --report compare.md
```

### 目标机与导入身份

先使用[模块身份检查器](../../tools/audit_module_identity.py)核对源码与实际安装模块。保留ELF、decision、census、编译/链接日志、消耗决策和工具身份，再对当前输入直接运行上述模块接口。诊断参数和范围见[开发与诊断](diagnostics.md)。

`tools/k3-gate-source-audit.sh` 是针对既有GCC目录结构的专用入口，其中历史stage/路径不能直接套到llama。需要重用时先核对脚本参数与输入身份；不能把logged wrapper文本交给shell执行。

## 输入

### 对照名单，与被审构建实际消费的决策

`--gate-list` 给出的是**对照名单**：gate2 的目标名单，审计用它检查**两个**构建。这和对齐
"baseline 消费了什么"是两回事 —— `build-stack` 只启用 stack-object，名单是 `build-gate2` 才用的。
拿同一份目标名单对照两个构建，是为了让分组差分可比；它**不**表示 baseline 消费了这份名单。

被审构建实际消费的决策用 `--consumed-decision` 单独声明，**只用于证据绑定**（路径 + 哈希），
**不参与名称匹配**，落在 `parameters.consumed_decision`，并同时出现在 `evidence.consumed_decision`；
报告"输入身份"一节分开打印。JSON 里 `gate_list.role` 固定为 `comparison-target-list`，并带一句
`role_note` 说明这个区别。

对照对象是被审目标构建实际使用的固定决策，不用新版报告推荐名单代替。显式传入当前去重后的 `--expected-gate-count`，不沿用实现中的历史默认数；不符时保留 `gate-list-size-mismatch` 缺口。当前参考v32清单为1,245项，具体身份见[gate构建约束](../deployment/gate-build.md)。阶段标识按模块的 `audit --help` 选择，构建证据必须使用相同阶段。

### 两个决策角色不能互相替代

| 用途 | 用哪份决策 | 搞混的后果 |
|---|---|---|
| 名称覆盖核对（哪些候选没被名单覆盖） | **对照名单** `--gate-list` | 两个构建无法分组对比 |
| 构建证据绑定（census 属于哪次构建） | **实际消费的决策** `--consumed-decision` | 见下 |

绑定用对照名单会同时犯两个错：把"同阶段但换了名单的另一轮构建"的记录当成本次证据；以及**拒绝掉
真实的 baseline 证据** —— `build-stack` 只启用 stack-object 插件，它消费的是一份 stack-only 决策，
那份诚实记录的哈希永远不可能等于 gate2 的对照名单。

因此：**未声明实际消费决策时，所有 census 保持未绑定**，记为 `consumed-decision-missing` 缺口，
并在 `next_evidence_needed` 里点名要这份文件。不用对照名单顶替，也不假设两者相同。

⚠️ 聚合日志里的 `gate list: N function(s)` **只证明名单被传入编译**。它不证明任何函数被命中、
被阻止或被消除。新版检查报告的推荐名单只作为 `check_report_reference` 旁证，哈希不一致会单列缺口。

### census

`implicit-vector-census<TAB>机制<TAB>函数名<TAB>formed|blocked`，四列。解析时校验：列数、
标签、动作集合、机制名非空、函数名非空。未知机制名**保留并标记**（丢弃它会把"有记录"变成"没记录"
而无人知道）；同一函数同一机制同时出现 `formed` 与 `blocked` 时两个动作都保留并记为
`census-action-conflict` —— 冲突不得被集合合并掩盖。

函数名按 `C1→C2`、`D1→D2` 归一，与 census 报告一致。

### 证据清单

`chimera-gate-source-evidence-v1` JSON。`artifact` 是这份 census 所属的**产物**（链接产物），
`compile_units` 声明编译单元，工具链身份必须是 sha256 摘要：

```json
{
  "format": "chimera-gate-source-evidence-v1",
  "stage": "build-gate2",
  "artifact": {"path": "xgcc", "sha256": "…"},
  "decision": {"path": "...", "sha256": "..."},
  "toolchain": {"xgcc": "...", "xgcc_sha256": "…64 hex…", "cc1": "...", "version": "..."},
  "compile_units": [{"name": "libbackend.a", "compile_command": "...", "census": "..."}],
  "census": [
    {"path": "...", "sha256": "...", "compile_unit": "...", "toolchain": "…64 hex…",
     "artifact": {"path": "...", "sha256": "..."}}
  ]
}
```

`artifact` 可写在清单级，也可逐条覆盖；`toolchain` 可写在清单级或编译单元上。缺哪一项，
`_bind_evidence` 就按那一项写拒绝理由。

## 证据等级

一份 census 记录只有在**整条链**都成立时才算证据，而且每一环都对**记录之外的东西**：

| 环节 | 核对对象 | 只声明不核对会怎样 |
|---|---|---|
| 文件身份 | 清单点名了该文件 | — |
| 内容 | 文件字节的 sha256 与清单声明一致 | 记录可以事后被改写 |
| 阶段 | 清单的 `stage` 等于被审阶段 | 另一轮构建的记录被拿来用 |
| 决策 | 清单声明的决策哈希等于**被审构建实际消费的决策**哈希 | 换了名单的另一次构建仍然"绑定" |
| **产物** | `artifact.sha256` 等于被审 ELF 的哈希 | 同阶段同决策的**另一次构建**挂到当前产物上 |
| 编译单元 | 名字出现在 `compile_units` 里，且带编译命令 | 一个不存在的单元名也能过 |
| 工具链 | 是 sha256 摘要，且与该编译单元一致 | `"placeholder"` 与真摘要无法区分 |

任一环断开记为 `census-evidence-unbound` 缺口，并逐条写出断在哪；该记录**降级为未验证旁证**。
未声明实际消费决策时另有一条 `consumed-decision-missing` 缺口，说明本次整体未做绑定。

census 文件按**解析后的路径**匹配：同一文件写成 `./census.tsv` 或绝对路径不会被当成"没有证据"。
这只放宽写法，上面七项一项都不放宽。

绑定关掉的是**误用**，不是**说谎**：一个精心编造的清单仍可能自洽。所以每一项在报告里逐条打印，
而不是压成一个布尔值 —— 让人能看出"哪里对上了、哪里没有"。

| 等级 | 含义 | 能推出什么 |
|---|---|---|
| 已绑定 `blocked` | 该函数在该次编译中确实被 gate 阻止 | gate 有执行证据（仍不是逐函数证明） |
| 已绑定 `formed` | 该函数在名单内却仍生成了隐式向量代码 | 是否算失败取决于阶段，见下 |
| 未绑定记录 | 有记录但无法关联到本次构建 | **什么也推不出**；不能判绕过，也不能证明生效 |
| 冲突（`conflict`） | 同函数同机制同时 `formed` 与 `blocked` | **两者都不计为证据**；不可升级为生效或绕过 |
| 机制未识别（`unrecognised`） | 机制名不在当前可解释的四种里 | 记录保留，但**不计为证据** |
| 无记录 | 没有任何编译期证据 | 证据不足 |

冲突与未识别排在确定性判定**之前**：一组自相矛盾、或无法解释的记录，不能被"平均"成一个结论。

### 已绑定 `formed` 的含义随阶段而变

`formed` 记录说的是"生成了隐式向量代码"，但**"绕过"需要有一个可被绕过的 gate**。
`build-stack` 只启用 stack-object 插件，此阶段未启用 gate，允许生成向量指令。

| 阶段 | 已绑定 `formed` 的状态 | 报告措辞 |
|---|---|---|
| `build-gate2` / `unknown` | `gate-bypassed` | 函数在名单内却仍生成了隐式向量代码 |
| `build-stack` | `formed-before-gate` | 该阶段未启用 gate，属未启用 gate 时的生成结果，**不构成绕过** |

两者都留在待核验清单里 —— 阶段本身不能证明 gate 效果，只是这个阶段**不可能**发生绕过。

因此条目上同时保留两个互相独立的判定：`status` 说源头/证据的结论，`evidence_status` 说证据的质量。
证据标签本身保持阶段中立（"名单内仍生成隐式向量代码"），是否算绕过的判断由 `status` 承担。
两个状态应分别记录，汇总的 "N function(s)" 不能说明每个函数的处理情况。

## 待核验清单为什么不含歧义条目

`status` 只是待核验的**一个**理由。同名（或变体）匹配到多个定义时，编译期记录尚未区分这些定义，
**逐函数核验就没有完成** —— 哪怕这份记录本身干净、已绑定。所以条目上另有 `pending`：
`status ∈ 待核验集合` 或 `ambiguous` 二者之一成立即为真。`status=blocked-evidence` 且
`pending=true` 并不矛盾，它说的是"这份记录干净，但它没证明它声称证明的那个函数"。
报告里会写明原因是"源头或证据未决"还是"同名定义未区分"。

## 输出含义

### JSON（`chimera-gate-source-audit-v1`）

| 字段 | 内容 |
|---|---|
| `elf` | 路径、SHA256、函数数、指令数 |
| `parameters` | `min_vlen_bits`、`stage`、`expected_gate_count`、`consumed_decision` |
| `assumptions` | 当前假设全文与排除的来源类型 |
| `evidence` | 每个 census 文件的绑定结果与**每一项绑定输入**（阶段、记录的决策哈希 vs 实际消费的决策哈希、编译单元是否在清单内、编译命令、工具链、产物哈希、声明哈希），以及 `consumed_decision` 与 `comparison_list_sha256` |
| `candidates` | 逐项候选源头（地址按角色分：`allocation`/`release`/`stores`/`loads`/`scopes`/`loops`） |
| `candidate_summary` | 总数、活跃数、假设下排除数、按类型计数 |
| `affected_sites` | 未解析调用点 → 贡献来源 ID，以及其中被假设排除的 ID |
| `propagation` | 调用指令数、已解析/未解析/空目标集、固定点轮数、活跃与不活跃站点、交叉核对结果 |
| `vector_code_functions` | 含向量指令的函数，单列，标注是否有候选源头与是否在名单内 |
| `gate_list` | 名单身份与 `role`、去重统计、规模核对、逐条核验结果、`pending` 与状态/证据计数 |
| `gaps` | 全部缺口（见下） |
| `answers` | 两个问题的直接答案（待核验条目带 `pending_reason`） |
| `check_report_reference` | 新版报告的交叉参照（仅旁证） |
| `next_evidence_needed` | 由缺口推出的下一步取证清单 |

### CSV

`--candidates-csv` 一行一个候选源头，可按 `kind`、`excluded_by_assumption`、`list_status` 筛选。
`--gate-csv` 一行一个原名单条目，可按 `status`、`evidence_status`、`pending`、`census_*` 筛选
（`census_conflicted_mechanisms` 与 `census_unrecognised_mechanisms` 单列，两者都不计为证据）。

### 中文报告

报告的章节顺序对应本页的四个问题：范围与假设、输入身份、证据绑定状态、候选源头总览、
传播与影响站点、问题一（漏项）、问题二（待验证清单 + 状态计数 + 证据质量计数）、
归属歧义与未覆盖、缺口、下一步证据。

## 归属歧义与缺口

共享的帧/setup 标记是一个 *may* 属性，多个分配可以共享同一个标记。因此**不按地址取最近的那个**
充当唯一归属：从每个已记录的分配出发，沿 CFG 走，且每一步都要求该标记确实活跃；能追溯到调用点的
分配**全部**保留。唯一来源才关联；多个来源保留候选集合并记 `ambiguous-frame-origin` /
`ambiguous-setup-origin`；无来源可归则记 `unattributed-frame-marker` / `unattributed-setup-marker`
并生成 `unattributed-activity` 兜底候选；没有被任何已枚举来源认领的活跃状态记
`unattributed-live-object`。无法归属的活动保留为保守候选，不受该假设排除。

**两个标记的追踪方向相反**，走错方向会静默地把一个真实来源变成兜底来源：

| 标记 | 状态怎么来的 | 走哪边 | 走反的后果 |
|---|---|---|---|
| 帧（`vlen_stack_frame`） | 在分配处创建，沿后继传播 | 分配 → **后继** | 找不到分配 |
| 准备区（`vlen_stack_setup`） | 反向依赖：从分配沿前驱走到 VLEN 值还活着的地方 | 分配 → **前驱** | 找不到分配，站点落进不可排除的兜底来源 |

准备区位于分配**之前**（`ld s1,0(s2)` / `jalr a3` / `sub sp,sp,s1` 这种形状里，调用点就在准备区
内）。走反了会把它记成 `unattributed-setup-marker` 并归入兜底来源 —— 而兜底来源不可被假设排除，
这会错误扩大被假设排除的范围。两个追踪方向均由真实分析器回归测试覆盖。

传播是候选 ID 集合上的有限工作队列固定点（单调并集，有限域，因此递归不会发散，也不需要枚举完整
路径）。结果会与分析器自己的闭包**交叉核对**；不一致记为 `closure-mismatch` /
`affected-site-mismatch` 缺口，不作静默归因。

站点是否活跃在传播**之后**判定：局部贡献为空、但继承集合非空的调用点是活跃的。只看局部集合会把
这类站点报成不活跃 —— 这正是生产分析器不会同意的那一版统计。

## 跨构建差分

`compare` 按 `(函数, 来源类型)` 分组，两边都输出**数量和各自地址**。地址只在各自的 ELF 内有效，
不能直接配对。缺少逐分配身份关联时，`linkage.per_allocation_identity` 为 `false`，报告只说"该类来源
在该函数下消失"，**不宣称某一处分配被精确消除**。同理，`baseline` 里消失不等于已证明安全 ——
还需要 gate 执行证据。

## 不能推出的结论

- 审计完成 ⇒ 应用安全。不成立。
- census 里有 `blocked` ⇒ gate 对**每个**函数都生效。不成立，只有该文件的绑定范围内算证据。
- census 里有 `formed` ⇒ gate 被绕过 —— 只有当该文件已绑定本次构建时才成立，且该阶段必须**启用**
  了 gate；`build-stack` 的 `formed` 是未启用 gate 时的生成结果，记 `formed-before-gate`。
- 对照名单 ⇒ 可以用作证据绑定的决策。不成立；两者的哈希不同是常态，混用会误拒真实记录。
- 没声明实际消费的决策 ⇒ 用对照名单顶上。不成立；所有 census 保持未绑定，
  记为 `consumed-decision-missing` 缺口。
- 同一个函数同机制既 `formed` 又 `blocked` ⇒ 任选一个当结论。不成立；冲突两者都不算证据。
- 机制名看不懂 ⇒ 当成没记录。不成立；记录保留并报为未识别，但它不构成证据。
- 记录"绑定"了 ⇒ 清单可信。不成立；绑定只会排除误用，编造的清单仍可能自洽 —— 逐项绑定输入会被
  打印出来供人核对。
- 只有同名函数中的一个 ⇒ 该名字核验完成。不成立；歧义独立阻止条目退出待核验清单。
- 最终 ELF 里还有向量指令 ⇒ 来自隐式向量化。不成立；只能证明残留，显式向量代码同样会产生它。
- 名单里找不到符号 ⇒ 该函数被内联/克隆/消除了。不成立；这只说明符号不在最终 ELF，
  逐函数命中必须有编译期记录。
- 候选源头在 `baseline` 有、在被审构建没有 ⇒ 该分配被消除了。不成立；只能按符号与类型分组说明
  该类来源消失。
- 同名函数、克隆、内联情况下的"命中"。不成立；它们单列在待核验清单里，需要
  逐 TU 的插件命中记录或 IR 清单才能区分。
- 排除项 ⇒ 已证明安全。不成立；排除是假设，未经证明。

## 边界

本审计**不**改变 check-elf 的任何结论，也不更新任何检查凭证。它对现有构建只读，对 `$RUN` 只新增
结果目录。如果审计结论与 check-elf 的结论冲突，冲突本身是待查项，不是可以任选其一的意见。

相关：协议边界见 [safety-v1.md](abi/safety-v1.md)，离线分析阶段见 [offline.md](architecture/offline.md)，
构建与测试入口见 [build-and-test.md](build-and-test.md)。
