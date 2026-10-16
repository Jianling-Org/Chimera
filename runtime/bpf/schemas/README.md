# BPF 映射表结构

已固定的 uprobe 队列使用 32 位小端不透明键，以及在
`runtime/interfaces/uapi/chimera_uprobe.h` 中声明的 176 字节
`struct chimera_uprobe_info`。Python 使用匹配的 `<Q20QiB3x` 布局，并通过固定字节样本验证编码一致性。
