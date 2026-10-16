# 协议与 ABI

本目录定义生产者与消费者之间的文件、符号和二进制约定。算法的推导与策略说明见 [安全点专题](../architecture/safepoints/README.md)，组件如何消费工件见 [架构总览](../architecture/README.md)。

| 接口 | 当前版本 | 主要参与者 |
|---|---|---|
| [Workspace Manifest](manifest-v2.md) | 2 | 离线 registry、安装器、Python 校验器、C Runtime |
| [Runtime ABI](runtime-v1.md) | 1 | 场景构建器、launcher、Runtime、翻译器 |
| [安全表 ABI](safety-v1.md) | 1 | 安全点分析、补丁步骤、Runtime |
| [地址映射 ABI](offset-map-v1.md) | 1 | 翻译与映射步骤、Runtime 查询 |
| [编译器元数据](compiler-metadata.md) | 当前节格式 | patched LLVM、插件、安全分析读取器 |
| [BPF 注册接口](bpf-uprobe.md) | 当前队列布局 | Python 注册器、配套内核 |

接口版本分别管理。安全检查实现版本用于使检查凭证失效，不能与安全表 ABI、Manifest 版本或软件包版本混为一谈。算法增加一个分类原因，不必然要求改变地址/布尔值安全表的二进制布局。

## 修改接口时的约束

先确认变化属于记录结构、能力的二进制布局，还是检查条件与算法语义。改变已有消费者解释的字段、符号或语义时，需要明确的版本边界，并同步生产、Python 校验和 C 消费路径。

新增可选报告可以使用现有 Manifest 的工件记录表达。运行时必需能力则必须有对应校验器和装载处理器；声明 `required_by=runtime` 不会自动生成消费者。

本目录描述当前实现，不承诺任意外部插件二进制兼容。接入点和验证步骤见 [扩展机制](../architecture/extensibility.md)。

