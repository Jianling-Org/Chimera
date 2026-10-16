# RISC-V 静态二进制翻译器

源码位于 `src/riscv/`：`frontend/` 和 `codegen/` 提供共用程序分析与控制流生成，`extensions/rvv/` 和 `extensions/spacemit_ime/` 实现扩展翻译。

| 入口 | 用途 |
|---|---|
| `rvv_sbt.py` | RVV → 标量 RV64 |
| `rvv_sbt_rvv.py` | RVV1024 → RVV256 |
| `rvv_sbt_rvv1024.py` | RVV256 → RVV1024，实验性过渡后端 |
| `ime_sbt_rvv.py` | 预展开 IME 符号汇编 → 原生 RVV1024；独立于迁移状态 ABI |

从本目录运行：

```sh
python3 rvv_sbt_rvv.py -c 'vadd.vv v8, v16, v24' --init-vtype 'sew=32,lmul=1' --raw
```

从仓库根目录运行 `make translator-test`。测试需要 pytest；部分执行回归需要 RISC-V 工具链和 QEMU，缺少工具会跳过。整程序翻译还需匹配的编译器、链接器与 `readelf`，交叉宿主机应显式选择工具；详见使用方法中的依赖与交叉工具链说明。

- [使用方法](../../../doc/integration/translator.md)
- [架构](../../../doc/developer/architecture/translator.md)
- [测试与验证](verify/README.md)
- [当前限制](../../../doc/developer/translator/limitations.md)

源码随仓库提供；wheel 暂不携带翻译器。Profile 继续通过 `config.translators[].translator_path` 指定入口的绝对路径。
