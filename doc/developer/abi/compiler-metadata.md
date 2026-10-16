# 编译器元数据

patched LLVM 与 Chimera 插件向 ELF 写入分析所需的事实。应用集成者通过正式检查生成的编译入口使用这些能力，操作流程见 [集成命令](../../integration/cli.md)。

本页描述当前 RV64、小端目标的节格式。最终链接 ELF 中的地址与可重定位对象中的地址表达不同，读取器应按相应产物阶段解释。

## 栈对象节

`.chimera.stackobj_map` 为机器指令与编译器栈对象的关联。每条记录为 12 字节，没有额外字段间填充：

```text
[u64 LinkedVA][u32 SOID]
```

`LinkedVA` 是最终链接后的指令虚拟地址，与反汇编中的链接地址处于同一空间；`SOID` 为编译器赋予的栈对象标识。读取最终 ELF 时，不能再次叠加模块加载基址。

这一地址约定同时适用于 `ET_EXEC`、零基址 `ET_DYN` 和非零基址 `ET_DYN`。`ET_REL` 对象仍使用节、偏移和重定位表达地址，不能直接与最终链接地址比较。

读取器校验记录长度和同一地址的冲突。最终地址正确只是完整性的一部分，节存在并不能证明每个函数都获得完整插桩。

## 按函数选择分析模式

分析器先确定当前函数的 VLEN 敏感栈访问集合 `U`，再取其中有有效对象记录的集合 `M`：

| 情况 | 分析模式 |
|---|---|
| ELF 没有该节 | `binary-no-section` |
| 当前函数 `U` 完整覆盖 | `metadata-complete-coverage` |
| 存在敏感访问缺少有效记录 | `binary-incomplete-coverage`，整函数回退 |

完整覆盖时使用编译器对象身份；覆盖不全时使用该函数的二进制分析，不能把两种对象身份混合。空节、其他函数的记录或部分插桩都不能授权忽略本函数未记录的访问。

报告包含实际 `metadata_mode`、`access_mode`、覆盖计数和缺失位置。缺少记录是证据缺口，后续二进制分析继续判断；算法说明见 [栈活跃性](../architecture/safepoints/stack-liveness.md)。

## 间接调用目标节

`.chimera.function_pointer` 提供间接调用点的可能目标集合，每组采用：

```text
[u64 CallVA][u32 Count][u64 TargetVA ...]
```

`Count` 决定后续目标地址数量，地址同样属于最终链接地址空间。读取器独立解码并校验长度，不能从栈对象节的存在推断函数指针元数据也存在。

函数指针元数据用来补充调用目标集合。它不能单独闭合已知外部调用，也不能证明调用者保存的 VLEN 敏感内容已死亡；相关传播见 [调用边界](../architecture/safepoints/call-boundaries.md)。

## 编译 gate 与重新检查

stack-object 插件提供对象事实，function-pointer 插件提供目标事实，vector-gate 插件应用函数级隐式向量化决策。它们是分别选择的能力。

gate 不会把显式 RVV intrinsic 自动变成目标无关实现，也不直接签发新 ELF 的通过凭证。使用固定计划完成编译后，仍要对最终链接 ELF 严格复检，并以实际携带元数据和实际二进制行为判断。

Profile 声明需要的元数据必须与最终 ELF 相容。当前分析可接受 ELF 携带额外元数据，但每函数完整性仍由读取和覆盖检查决定。

## 实现与验证

- [元数据读取器](../../../preprocessing/offline/analysis/safety/stack_liveness/model.py)
- [LLVM 插件构建入口](../../../preprocessing/offline/toolchain/llvm-21.1.0/plugins/CMakeLists.txt)
- [链接地址回归](../../../tests/test_stackobject_metadata_addresses.py)
- [完整覆盖与回退回归](../../../tests/test_metadata_coverage_fallback.py)
- [元数据与 BPF 布局回归](../../../tests/test_metadata_and_bpf_abi.py)

