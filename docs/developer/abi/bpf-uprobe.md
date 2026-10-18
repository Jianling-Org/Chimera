# BPF 可迁移文件注册接口

当前注册器把应用及所需模块的实际文件 inode 提交到配套内核的 pinned BPF 队列。该状态属于目标机器，不随 `.workspace` 包传递；换位置安装或替换文件后，应重新验证和注册。

## 队列布局

键为 4 字节小端无符号整数，是不透明请求标识。当前 Python 编码格式为 `<I`，实现从 inode 与批次索引派生该值；消费者不能从键推导迁移路线或安全点语义。

值为 176 字节，对应 `struct chimera_uprobe_info`：

| 字节偏移 | 类型与大小 | 字段 |
|---:|---|---|
| 0 | `uint64_t`，8 字节 | `inode` |
| 8 | 20 个 `uint64_t`，160 字节 | `offsets` |
| 168 | `int32_t`，4 字节 | `offset_count` |
| 172 | `uint8_t`，1 字节 | `is_attached` |
| 173 | 3 字节 | 保留填充 |

Python 格式为 `<Q20QiB3x`。头文件中的静态断言约束总大小与 offsets 数组大小，Python 与 C 使用同一金样本验证布局。

## 当前注册语义

公开注册路径只提交零偏移文件通知：

```text
offsets[0] = 0
offset_count = 1
is_attached = 0
```

这表示把一个 ELF inode 宣告为可迁移文件。安全点已经在离线 `patch-safepoints` 阶段写入翻译 DSO，不通过这里逐条登记。

注册路径先核对 `--input` 主程序的 basename 与整文件摘要，再由包内加载器解析依赖路径，并为相应实际文件取得 inode。当前普通注册路径不执行 `run` 的逐依赖摘要循环，因此注册成功不能作为所有依赖内容已匹配的证明；启动时由 `run` 核对加载器报告的已记录模块。使用外部标量叶契约时，还会执行该契约要求的专门绑定复核。

## 环境与失败

目标机需要已有、布局匹配且可访问的 pinned map。Python 注册器不会通过安装 Workspace 自动创建所需内核能力。`chimera-user verify` 检查场景要求的宿主条件，注册时仍要处理文件、map 和提交错误。

实现支持批量更新并为不支持批量操作的环境提供相应回退。提交、重试和队列消耗由注册器与内核协调；命令完成不表示应用线程已经完成迁移。

应用替换、重新安装或重新生成工件后，应根据当前实际文件重新执行注册，不能携带另一台机器的 inode 或旧 BPF 状态。

公开操作见 [应用使用者命令](../../user/cli.md)，具体内核与信号要求见 [RVV 目标](../architecture/targets/rvv/README.md)。

## 实现与验证

- [C UAPI 定义](../../../runtime/interfaces/uapi/chimera_uprobe.h)
- [Python 编码与队列](../../../runtime/bpf/loader/chimera/bpf/registry.py)
- [注册事务](../../../runtime/bpf/loader/chimera/bpf/transaction.py)
- [Python 布局回归](../../../tests/test_metadata_and_bpf_abi.py)与 [C 布局回归](../../../runtime/tests/runtime/test_uprobe_layout.c)
