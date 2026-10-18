# 安全表 ABI v1

安全表表达原始程序中每个记录位置的迁移安全分类。算法与条件范围见 [安全点分析](../architecture/safepoints/README.md)，本页只定义产物身份、地址与消费接口。

## Manifest 记录与地址

安全 ELF 工件归属于模块，使用 `capability=safety`、`representation=elf`、`abi=1`，由 Runtime 消费。当前安全分析步骤为主程序生成安全表。

分类采用原指令执行前状态。表中的 `original_rva` 是原始链接地址减去输入 ELF 的加载基址，与翻译 DSO 中的位置分开。Runtime 根据实际模块基址转换地址；安全事实不能通过替换为翻译地址重新定义身份。

## ELF 符号与布局

令 `P` 为 `chimera_` 加经过符号规范化的模块标识，生成器导出：

| 符号 | 类型与内容 |
|---|---|
| `P_safety_abi` | `uint64_t`，值为 1 |
| `P_safety_entries` | 按原始 RVA 排序的记录数组 |
| `P_safety_count` | `uint64_t`，数组记录数 |

每条记录为两个 64 位无符号字段：

```c
struct chimera_safety_entry {
    uint64_t original_rva;
    uint64_t is_safe;
};
```

`is_safe` 的导出值为 0 或 1。数组同时包含安全与不安全记录，不能把 `count` 当作安全点数量。具体的翻译陷阱补丁由离线步骤按照分类和地址映射生成。

## JSON 分析产物

当前准备步骤还生成 `format=chimera-safety-v1` 的内部 JSON，主要供诊断、补丁步骤与开发回放使用；它不默认登记为正式 Manifest 工件。

| 顶层字段 | 含义 |
|---|---|
| `unknown_stack_size_policy` | 本次选择的未知标量栈尺寸策略 |
| `assumption` | 与策略对应的范围假设 |
| `conditional` | 是否为条件性分析范围 |
| `scope_exclusion_count` / `scope_exclusions` | 按范围假设排除的分配及其证据或缺口 |
| `entries` | 逐位置的安全事实 |

每条 entry 含 `address`、`address_hex`、`original_rva`、`safe`、`unsafe_reasons`、`vector_live` 和 `stack_live`。`address` 属于原始链接地址空间；`original_rva` 是按模块基址归一化后的值。

当前分类原因包括向量寄存器活跃、向量栈数据、VLEN 栈帧准备值、动态栈帧和本地实际宽度缓存等。原因字符串由分析实现生成；算法增加诊断维度与安全表二进制 ABI 是分别管理的变化。

继承跟踪导出 `chimera-inheritance-trace-v1`，记录 seed 调用边、首次继承来源与深度。正式 `check-elf` 的综合报告及继承诊断有自己的格式，不能把内部安全 JSON 当作整次检查结果。

## 范围与凭证

默认未知尺寸策略是 `conservative`。显式选择 `assume-scalar-independent` 后，报告持续标明条件范围；即使当次没有排除条目，也不能改写成无条件证明。

范围元数据保留在分析报告与检查条件中，ELF 的两字段布尔安全表不携带完整策略说明。准备流程必须先校验与 ELF 内容、分析版本和有效参数绑定的检查凭证，不能只读取一张安全表决定准入。

本地标量宽度、终端路径、调用继承、预算及排除规则以 [算法专题](../architecture/safepoints/README.md) 为准。当前检查实现版本变化会使旧凭证失效，不意味着本 ABI 的版本号也随之递增。

## 外部标量叶函数产物

使用内容绑定的外部标量叶证明并实际闭合调用边界时，准备步骤可额外发布模块所有的 `external-scalar-leaf-contracts/json` 工件，ABI 为 1，`required_by` 包含 `launch`。

格式标识为 `chimera-external-scalar-leaf-v1`，包含证明、输入 ELF 身份和闭合调用。launcher 重新核对实际绑定；它不会把调用者中仍活跃的状态改成安全。详细条件见 [调用边界](../architecture/safepoints/call-boundaries.md)。

## 实现与验证

- [分类器](../../../preprocessing/offline/analysis/safety/classifier.py)
- [导出器](../../../preprocessing/offline/analysis/safety/exporters.py)与 [工件登记](../../../preprocessing/offline/analysis/safety/step.py)
- [Runtime 结构](../../../runtime/interfaces/abi/chimera_runtime.h)与 [加载器](../../../runtime/artifacts/manifest/linux_riscv64_rvv_v1/capability_loaders.c)
- [产物回归](../../../tests/test_safety_artifacts.py)
