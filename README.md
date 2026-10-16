# Chimera

Chimera 为已有 ELF 应用生成离线分析与翻译工件，使线程能够在不同向量长度的执行环境之间转换。当前运行目标是 Linux／RISC-V64／RVV，提供 `chimera-dev`、`chimera-pkg`、`chimera-user` 三个命令入口。

## 阅读入口

- [文档总览](doc/README.md)
- [系统开发与构建](doc/developer/README.md)
- [应用集成、检查与交付](doc/integration/README.md)
- [应用运行与迁移](doc/user/README.md)
- [LLVM 与 SVF 源码准备](doc/external-dependencies.md)

## 源码与安装

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e .
chimera-dev --help
chimera-pkg --help
chimera-user --help
```

Python 要求 3.11 及以上。安装 Python 命令不会自动准备 LLVM 源码、工具链插件或目标内核支持；真实检查、prepare 及迁移所需条件见[构建与测试](doc/developer/build-and-test.md)及[LLVM/SVF 源码准备](doc/external-dependencies.md)。

| 目录 | 内容 |
|---|---|
| `cli/` | 开发、集成、运行命令及打包接口 |
| `preprocessing/offline/` | 离线工作流、安全点分析、配置、LLVM 插件与补丁 |
| `runtime/` | 运行时、ABI、装载器、BPF 及 C 回归 |
| `tests/` | Python 回归及固定测试输入 |
| `tools/` | 源码树构建、诊断与回归辅助，不属于安装后的用户命令 |
| `examples/` | 样例源码、补丁、Profile 与脚本，不含模型、第三方源码或 scalar 二进制 |
| `doc/` | 当前正式文档 |
