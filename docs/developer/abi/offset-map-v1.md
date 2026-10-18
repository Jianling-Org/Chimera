# 地址映射 ABI v1

地址映射连接原始模块与某个翻译变体。一个模块的不同方向拥有独立变体、映射工件和符号命名空间。安全表负责原始位置的事实，映射负责地址对应。

## 工件与导出

Manifest 中映射工件为变体所有，使用 `capability=offset-map`、`representation=elf`、`abi=1`，由 Runtime 消费。

令 `P` 为 `chimera_` 加经过符号规范化的变体标识，导出为：

| 符号 | 内容 |
|---|---|
| `P_offset_map_abi` | 64 位 ABI 标识，值为 1 |
| `P_forward_entries` / `P_forward_count` | 原始 RVA → 翻译 RVA 的有序表及数量 |
| `P_reverse_entries` / `P_reverse_count` | 翻译 RVA → 原始 RVA 的有序表及数量 |

```c
struct chimera_offset_entry {
    uint64_t original_rva;
    uint64_t translated_rva;
};
struct chimera_reverse_entry {
    uint64_t translated_rva;
    uint64_t original_rva;
};
```

正向表按原始 RVA 排序，反向表按翻译 RVA 排序。数量字段为 `uint64_t`，C 装载器还会检查可表示范围。

## 地址归一化

映射步骤先从翻译汇编及其反汇编提取已链接入口，再分别减去原始 ELF 与翻译 DSO 的加载基址：

```text
original_rva   = original_linked_address - original_load_base
translated_rva = translated_linked_address - translated_load_base
```

运行时加入本次实际装载基址，查询对应模块和变体。文件偏移、原始链接地址、RVA 和运行期地址是不同概念，不能在表中混用。

映射 JSON 的格式标识为 `chimera-offset-map-v1`，entry 字段 `original`、`translated` 及其十六进制形式表示上述归一化值。当前 JSON 是准备与回放中间产物，正式发布的是已登记的映射 ELF。

## 精确入口与安全点补丁

迁移入口必须对应当前翻译器的完整入口状态。某条源指令可能展开成辅助序列，不能假定每条生成指令都可反向恢复。

`patch-safepoints` 根据安全事实和正向映射，在翻译入口以等长陷阱替换当前指令槽。补丁不改变后续地址，已有映射继续有效。重建补丁从经过校验的未打补丁副本开始，避免上轮补丁残留。

退出翻译需要精确的反向记录。缺失时必须按场景的失败路径处理，不能用前一条、后一条或最近地址替代。运行时陷阱的诊断与终止语义见 [Runtime 架构](../architecture/runtime.md)。

## 与其他契约的关系

映射的所有者、翻译 DSO 与变体属性应一致。Manifest 文件摘要用于确认映射文件内容；翻译代码指纹用于绑定变体身份。只把文件名改成另一个方向不会改变实际能力。

修改入口标签或翻译器输出组织时，同步核对标签解析、函数入口、符号字符、地址归一化、重建回放和 Runtime 查询。保持 ELF 表布局不代表这些语义变化可以绕过验证。

## 实现与验证

- [映射提取与导出](../../../preprocessing/offline/analysis/offsetmap/codegen.py)
- [映射步骤与工件登记](../../../preprocessing/offline/analysis/offsetmap/step.py)
- [Runtime 表结构](../../../runtime/interfaces/abi/chimera_runtime.h)
- [映射产物回归](../../../tests/test_offsetmap_artifacts.py)
