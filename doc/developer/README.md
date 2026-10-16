# Chimera 开发者指南

Chimera 开发者维护离线分析与翻译流程、运行时、目标适配、公共协议和系统发布工具。开发者通过明确的步骤与目标契约扩展系统，并为扩展补充验证；应用 Profile 的配置和应用交付见 [应用集成者指南](../integration/README.md)。

## 阅读顺序

1. [架构总览](architecture/README.md)：理解组件与离线、在线分工。
2. [构建与测试](build-and-test.md)：准备开发环境和工具链，选择验证层次。
3. [命令参考](cli.md)：使用开发工具链与步骤重建命令。
4. [扩展机制](architecture/extensibility.md)：实现步骤、目标、场景或工件能力。
5. [协议与 ABI](abi/README.md)：核对跨组件接口。
6. [系统发布](releasing.md)：从已构建产物生成平台 wheel。

分析行为的设计说明统一在 [安全点分析算法](architecture/safepoints/README.md)。排查问题与核对实际安装版本见 [诊断指南](diagnostics.md)。

## 开发闭环

先安装源码开发环境并运行适用的基线检查，再在对应模块实现改动。新增步骤需要声明输入、输出、参数和失败条件；新增运行时能力需要同时维护生产者、Manifest 记录、校验器和消费者。

```bash
make develop
make python-test
make portable-c-test
```

这些命令从仓库根目录运行，依赖与目标约束见 [构建与测试](build-and-test.md)。发布前还需要完成所选目标上的构建、装载和迁移验证；本地 Python 或可移植 C 测试只覆盖各自的验证范围。

## 向其他角色交付

开发者交付 Chimera wheel 与对应的目标能力说明。接口变化时同步更新 [Profile 说明](../integration/profiles.md)、[命令参考](cli.md) 及相应 ABI 文档，使应用集成者可以依据明确的接口准备工件。

