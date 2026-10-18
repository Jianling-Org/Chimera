# RVV SBT 文档入口

本目录保存翻译器的长期设计说明、接口约束、当前支持矩阵和验证规则。文档说明使用方法、接口与验证范围，支持情况与 dispatcher、handler 及测试保持一致。

## 推荐阅读顺序

1. [根目录 README](../README.md)：安装、命令行和常用 API。
2. [架构说明](ARCHITECTURE.md)：解析器、CFG/vtype 分析、控制流、状态层、翻译方向几何、后端和输出层的职责边界。
3. [支持指令矩阵](SUPPORTED_INSTRUCTIONS.md)：三个翻译模式当前注册的 opcode，以及“注册”和“已验证”的区别。
4. [模拟状态 ABI](STATE_ABI.md)：`simulated_cpu_state` 的固定偏移、TLS 状态基址和迁移约束。
5. [验证流程](../verify/README.md)：从 Python 回归到 RISC-V 目标机语义验证的证据边界和操作命令。

架构说明中的“翻译方向几何的唯一权威”一节定义了当前两个方向
（`128→32`、`32→128`）及其派生量的唯一来源 `src/riscv/extensions/rvv/runtime/geometry.py`；
新增方向或修改槽位布局前应先读该节。

## 设计与问题记录

- [已知问题](../TRANSLATOR_ISSUES.md)：记录 `-fPIC -shared` 下跨函数直接 `jal *_translated` 可能触发 `R_RISCV_JAL` 重定位范围错误。

## 测试与实验文档

- [结构和流程测试说明](../tests/README.md)：pytest fixture、生成汇编和测试职责。
- [标量语义验证](../verify/README.md)：翻译、交叉编译、QEMU/目标机执行流程。
- [RVV256 宽路径验证](../verify/rvv256_wide/README.md)：RVV256 宽 LMUL profile 的独立验证。
- [RVV1024 过渡验证](../verify/rvv1024_transition/README.md)：RVV256 紧凑状态到 VLEN=1024 目标机的过渡路径。

## 文档维护规则

### 哪些内容长期保留

- 稳定的输入/输出合同、状态 ABI、控制流映射、分析算法和验证边界；
- 能够由当前代码和测试复现的支持矩阵；
- 仍被脚本、测试或 `AGENTS.md` 明确引用的问题记录。

### 支持范围与实验结果

- 阶段计划中的历史统计、旧机器路径和旧覆盖率数字；
- 仅生成汇编、仅通过 pytest 或仅在宿主机运行的结果；
- OpenBLAS 单个 kernel 的成功结果；
- 工作树中的个人周报、截图、HTML 图和临时输出。

更新支持情况时，运行 `python3 tools/generate_support_docs.py`，并用
`python3 tools/generate_support_docs.py --check` 核对 registry；不要手工维护
dispatcher、preflight 和文档三份 opcode 白名单。后端工程质量门禁
`python3 tools/check_backend_quality.py` 会拒绝在后端内联方向几何/LMUL
字面量、状态基址标记和 bare except 等回归。
