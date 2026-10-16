# RISC-V 静态二进制翻译器

## 入口与依赖

翻译器位于 `preprocessing/translator/rvv_sbt_tool/`，下面的命令从该目录运行。需要 Python 3.11 及以上；核心实现只使用标准库和本目录的 `src/riscv/`。

| 入口 | 输入与输出 | 定位 |
|---|---|---|
| `rvv_sbt.py` | RVV → 标量 RV64G | 内存模拟向量寄存器与 CSR |
| `rvv_sbt_rvv.py` | RVV1024 → RVV256 | 分块执行并逐条写回源状态 |
| `rvv_sbt_rvv1024.py` | RVV256 → RVV1024 | 实验性迁移过渡后端 |
| `ime_sbt_rvv.py` | 预展开 IME 符号汇编 → 原生 RVV1024 | 不使用迁移状态块或 offset map |

源码随仓库提供，wheel 暂不携带翻译器。Chimera Profile 通过 `config.translators[].translator_path` 指定入口的绝对路径，见 [Profile](profiles.md)。

## 命令行

```sh
# RVV 片段：三个 RVV 入口都接受 -c、--init-vtype 和 --raw
python3 rvv_sbt.py -c 'vadd.vv v8, v16, v24' --init-vtype 'sew=32,lmul=1' --raw
python3 rvv_sbt_rvv.py input.s -o translated.S
python3 rvv_sbt_rvv1024.py input.s -o translated.S

# IME 入口只接受文件输入；先展开宏、include 和汇编条件
python3 ime_sbt_rvv.py kernel.s -o kernel_rvv.s
```

三个 RVV 入口的常用参数：

| 参数 | 用途 |
|---|---|
| `-c` / 输入文件 | 提供片段或汇编文本，二选一 |
| `-o` | 输出文件，省略时写 stdout |
| `--init-vtype` | 设置分析初值，例如 `sew=32,lmul=2,ta,ma`；不向运行时状态块写入初值 |
| `--func-name` | 单函数输出名称 |
| `--raw` | 仅输出翻译块，不生成函数包装 |
| `--text-only` | 保留标签与正文，省略包装指示符 |
| `--state-base-mode` | `initial-exec`（默认 TLS 访问）或 `helper`（调用状态基址 helper） |

`--vlenb` 适用于标量和 RVV256 入口，默认 128；RVV256 入口只接受 128。反向入口使用 `--source-vlenb` 和 `--target-vlenb`，当前只支持 32→128。`--conservative` 仅适用于 RVV256 入口。IME 不支持上述 RVV 专用参数；各入口完整参数以 `--help` 为准。

默认 RVV 输出访问外部 TLS 状态，不会自动生成 `.comm simulated_cpu_state`。集成方需提供匹配的状态符号或 helper，详见[状态 ABI](../developer/abi/translator-state.md)。`--raw` 与 `--init-vtype` 都不会替调用方初始化运行时状态。

## 整程序翻译

向 RVV256 或反向入口额外传入库名，可启用 objdump 程序模式。RVV256 CLI 默认执行对象级跳转范围检查，因此除了 Python，还需要匹配的 RISC-V 编译器、汇编器、链接器和 `readelf`。

```sh
# 非 RISC-V 宿主机应指定实际安装的交叉工具链
python3 rvv_sbt_rvv.py cc1.dump cc1_vlen1024_to_vlen256 -o translated.S \
  --jal-range-fixup-compiler riscv64-linux-gnu-gcc \
  --jal-range-fixup-readelf riscv64-linux-gnu-readelf
```

范围检查的 CLI 默认命令为 `gcc` 和 `readelf`，假定它们是 RISC-V 构建工具。不能用宿主 GCC/Clang 代替。`--jal-range-fixup-compiler-arg` 可重复传入以替换默认参数，仍保留 `-fPIC`；应提供与最终构建一致的完整 ISA/ABI，例如使用 `--jal-range-fixup-compiler-arg=-march=...` 的形式。

大型程序按完整函数分组发射代码节，范围检查通过 `-nostdlib -r` 合并后检查对象地址。文件 CLI 使用临时函数存储，避免汇编器运行期间保留整份 Python IR。`TMPDIR` 应指向空间充足的磁盘目录；tmpfs 会占用内存预算。更新翻译结果后须重新构建译后 DSO，并根据最终链接地址生成 offset map。

## Python API

```python
from riscv.frontend.parser import AsmParser
from rvv_sbt import translate as translate_scalar
from rvv_sbt_rvv import translate as translate_rvv256

instructions = AsmParser().parse_string("vadd.vv v8, v16, v24")
scalar = translate_scalar(instructions, init_vtype="sew=32,lmul=1", raw=True)
rvv256 = translate_rvv256(instructions, init_vtype="sew=32,lmul=1", raw=True)
```

从翻译器目录设置 `PYTHONPATH=.:src` 后运行。`translate()` 接收指令列表，`translate_function()` 接收 `RVFunction`，程序 API 接收 `RVProgram`。

RVV256 的 `translate_file_with_jal_range_fixup(input_path, output_path=...)` 提供文件流式输出；已有 `RVProgram` 的调用方使用 `translate_program_with_jal_range_fixup()`。传入 `output_path` 时返回 `(None, fixed_sites)`，否则返回汇编文本与修正站点。两者默认编译器为 `riscv64-unknown-linux-gnu-gcc`，可通过 `compiler`、`readelf`、`compiler_args` 指定工具链。

## 支持范围与开发

- [支持矩阵](../developer/translator/supported-instructions.md)：由注册表生成，注册不等于完整语义验证。
- [当前限制](../developer/translator/limitations.md)：FOF、间接跳转、vstart 与实验后端边界。
- [IME 规范](../developer/translator/ime-rvv.md)：输入形式、寄存器布局与展开约束。
- [架构](../developer/architecture/translator.md)：解析、CFG/vtype、lowering、控制流与链接。
- [状态 ABI](../developer/abi/translator-state.md)：状态槽、TLS、方向和 Runtime 契约。
- [测试与验证](../../preprocessing/translator/rvv_sbt_tool/verify/README.md)：回归命令与各目标验证入口。
