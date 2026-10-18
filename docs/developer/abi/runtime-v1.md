# 运行时 ABI v1

Runtime ABI 连接 Workspace、场景运行时和翻译代码。通用运行时数据结构定义模块、代码范围、变体、正反向映射及安全表；具体路线、寄存器状态与迁移信号由场景规定。

## 工件身份与加载

Runtime 工件是 `owner_kind=workspace`、`owner_id=root`、`capability=runtime`、`representation=elf`、`abi=1` 的记录。Manifest 的 `runtime_abi` 必须与场景契约一致。

Python 校验器核对 ELF 类型、目标和必需导出。C Runtime 初始化独立读取 Manifest、验证产物摘要及能力契约，完成装载后发布可查询 registry。迁移信号路径使用已初始化数据，不能在 handler 中重新解析 Manifest、动态加载库或进行离线分析。

当前 RVV 场景要求 Runtime 导出：

```text
chimera_runtime_abi_v1
chimera_runtime_scene_linux_riscv64_rvv_v1
query_original_translated_map
simulated_cpu_state_riscv64_rvv_1024_riscv64_rvv_256
simulated_cpu_state_riscv64_rvv_256_riscv64_rvv_1024
get_simulated_cpu_state_addr_riscv64_rvv_1024_riscv64_rvv_256
get_simulated_cpu_state_addr_riscv64_rvv_256_riscv64_rvv_1024
```

标识值与场景 marker 同时参与兼容性检查。数组与访问函数的方向名称也属于跨层符号契约。

## 通用运行时对象

| 对象 | 主要字段与职责 |
|---|---|
| `chimera_registry` | 已装载模块数组及数量 |
| `chimera_module` | 模块标识、运行名称、原代码范围、安全表及变体列表 |
| `chimera_translation_variant` | 不透明 `route_id`、代码 body、翻译范围、正反向表及数量 |
| `chimera_safety_entry` | 原始 RVA 与 `is_safe` |

原始代码 body 为 0；非零 body 和 route 的含义由场景拥有。通用 registry 只比较身份，不能嵌入 VLEN 判断或根据变体名推断语义。

当前 RVV body 值为 `1=1024→256`、`2=256→1024`，方向枚举值为 `0=1024→256`、`1=256→1024`。body 与方向是两个不同枚举域，不能直接互换。RVV route 统一通过 `chimera_rvv_route_id` 派生。

## 翻译代码契约

令 `P` 为 `chimera_` 加经过符号规范化的变体标识，当前翻译 DSO 要提供：

| 导出 | 作用 |
|---|---|
| `P_translated_code_abi_v1` | 翻译代码 ABI 标识，值为 1 |
| `P_translation_fingerprint_<指纹>` | 与 Manifest 变体及端点属性绑定 |
| `<variant_id>_original_base_addr` | Runtime 填入原始模块实际基址 |

翻译范围、映射所有者与端点属性必须对应同一变体。不同方向的翻译 DSO 使用独立命名空间，避免双向装载时符号抢占。

### 可选no-link分派扩展

每个变体可以额外导出 `P_no_link_abi`（值为1）、`P_no_link_count` 和 `P_no_link_entries`。扩展表由工件哈希与翻译指纹绑定，存于只读重定位数据区。旧DSO没有此表时保留原有失败关闭路径，不能推定其支持新分派。

每项为四个uint64_t，共32字节：

| 字段 | 含义 |
|---|---|
| `trap_pc` | 装载重定位后的精确trap地址 |
| `frame_bytes` | 保留的query frame大小 |
| `target_slot` | frame内已验证目标所在字节偏移 |
| `original_rva` | 对应原始指令RVA |

条目必须排序且唯一；范围、frame大小、slot边界和目标均由registry校验。SIGTRAP仅在精确已注册站点接受稳定有效目标，恢复源寄存器后弹出已知frame并更改PC；不提交迁移、不切换variant、不发送ORIGINAL ACK。未知、零、奇地址或递归目标继续失败关闭。完整状态语义见[自动迁移](../../architecture/automigration.md)。

## 线程状态

RVV 场景为两个方向分别导出线程局部状态数组，当前每个数组容纳 4192 字节。翻译器共享逻辑布局大小为 `0x1040`；容纳尺寸不是可任意扩展字段的授权。

| 位置 | 含义 |
|---|---|
| `0x0000` 起的向量区 | 最大容纳 32 个 128 字节源寄存器槽；具体方向按源状态视图解释 |
| `0x1000` | `vstart` |
| `0x1008`、`0x1010` | 翻译器定义的 `vxsat`、`vxrm` 槽 |
| `0x1018` | `vcsr` |
| `0x1020` | `vl` |
| `0x1028` | `vtype` |
| `0x1030` | 源语义 `vlenb` |

1024→256 翻译使用 128 字节源寄存器槽；256→1024 过渡路径按 32 字节源寄存器步长解释紧凑状态。CSR 偏移保持固定，不能按目标硬件宽度整体缩放。

当前信号保存路径把配套 HMP 内核的分组向量区压紧到源寄存器布局，并保存 `vstart`、`vcsr`、`vl`、`vtype`、`vlenb`。不能假设每个翻译器辅助槽都由信号保存路径独立填写。布局、状态写回和具体信号协议见 [RVV 场景](../architecture/targets/rvv/README.md)。

proposal准备时，非零源`vstart`在写入translator TLS和COMMIT ACK之前被拒绝。handler返回PREPARE NACK，保留源CPU、PC和完整signal context；不清零restart index，也不移除translated内存lowering的保护。此限制不修改legacy packed state ABI。

## 失败与演进

Runtime 初始化未完成时不安装迁移处理器。当前 constructor 的初始化失败会报告错误并保持迁移禁用；它不等于应用进程必然退出。

退出翻译要求精确的反向映射。翻译陷阱 PC 无映射时按当前场景终止路径处理，不能用相邻映射或跳过指令恢复执行。生命周期与状态图见 [Runtime 架构](../architecture/runtime.md)。

修改共享结构、body 编号、状态偏移或导出符号时，同时更新分析/翻译生产者、Python 校验、C 装载和目标机测试。Manifest 版本变化不自动改变 Runtime ABI。

## 实现与验证

- [通用 Runtime 定义](../../../runtime/interfaces/abi/chimera_runtime.h)与 [RVV ABI](../../../runtime/interfaces/abi/linux_riscv64_rvv_v1/runtime_v1.h)
- [Runtime 工件契约](../../../runtime/artifacts/scene_contracts/chimera/scene_contracts/linux_riscv64_rvv_v1.py)
- [能力加载器](../../../runtime/artifacts/manifest/linux_riscv64_rvv_v1/capability_loaders.c)
- [翻译器外部输入说明](../../external-dependencies.md#翻译器)
- [向量状态搬运](../../../runtime/runtime/state/linux_riscv64_rvv_v1/vector_state.c)与 [状态回归](../../../runtime/tests/runtime/test_translator_state.c)
