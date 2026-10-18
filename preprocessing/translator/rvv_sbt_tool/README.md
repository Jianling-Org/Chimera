# RISC-V 静态二进制翻译器（SBT）

将 RISC-V Vector Extension (RVV) 汇编片段做静态翻译，支持两种稳定输出模式和一个实验性过渡后端：

- **标量模式**（`rvv_sbt.py`）：RVV → 标量 RV64G，通过 `simulated_cpu_state` 内存块模拟向量寄存器和 CSR
- **256-bit RVV 模式**（`rvv_sbt_rvv.py`）：1024-bit RVV → 256-bit RVV，strip-mining 拆分为 256/SEW 元素块，保留向量指令风格
- **RVV1024 过渡模式**（`rvv_sbt_rvv1024.py`）：RVV256 紧凑状态 → VLEN=1024 目标机，供迁移实验使用，尚不属于稳定后端

状态块的 CSR 区域（0x1000-0x1030）在两条路径中保持兼容，但向量
payload 的解释由翻译方向决定：1024→256 使用每个逻辑 vreg 128B 的布局，
256→1024 使用 RVV256 每个物理 vreg 32B 的紧凑布局。翻译块从所属状态块
读取并写回，不直接依赖另一条路径的状态符号。

## 项目结构

源码根目录为 `src/`。`riscv/` 承载共用程序表示、解析、控制流分析和代码生成；
`riscv/extensions/rvv/` 承载当前 RVV 扩展实现。当前支持范围仍集中在 RVV，
其他扩展可以复用共用层，但多扩展组合翻译尚未实现。

```text
rvv_sbt_tool/
├── rvv_sbt.py / rvv_sbt_rvv.py / rvv_sbt_rvv1024.py
├── src/riscv/
│   ├── frontend/              # 程序模型、输入解析、CFG 和调用图
│   ├── codegen/               # 控制流重写与对象范围检查
│   ├── registers.py           # RISC-V 寄存器名称与调用约定
│   └── extensions/rvv/
│       ├── instruction.py     # RVV 分类与 mask form
│       ├── analysis/          # 配置模型、状态机与 vtype 数据流
│       ├── translation/       # 准备、规格、分发、lowering 和块保护
│       ├── runtime/           # 布局、方向几何、TLS 与输出契约
│       └── backends/
│           ├── scalar/        # 标量执行；后端内部共用支撑
│           ├── rvv256/        # 规划与宽执行分离，各指令族独立
│           └── rvv1024_transition/
│               ├── operands.py / validation.py
│               ├── execution.py / state_view.py
│               ├── lowering.py / backend.py
│               └── handlers/
├── tests/
├── tools/
├── verify/
└── docs/
```

三个根目录入口继续支持直接运行和既有 Python API。入口负责定位同目录下的
`src/`，因此源码部署与 Chimera 打包后的脚本调用方式不变。
直接导入内部模块时，将 `src/` 加入 `PYTHONPATH`，例如：

```bash
PYTHONPATH=src python3 -c 'from riscv.frontend.analysis import analyze_structure'
```

共用层不导入 RVV；RVV 共用代码不导入具体后端；三个后端之间不互相导入。
入口负责选择具体后端。旧 `core/`、`models/`、`backends/` 内部路径已删除。

## 双方向输出契约

当前两个专用入口向目录外运行时发射以下固定 ABI。运行时必须以 TLS 对象
形式提供对应状态符号；本目录不定义或修改运行时查表实现。

| 入口 | 状态符号 | 查表函数 `a0` |
|---|---|---:|
| `rvv_sbt_rvv.py`（RVV1024→RVV256） | `simulated_cpu_state_riscv64_rvv_1024_riscv64_rvv_256` | `1` |
| `rvv_sbt_rvv1024.py`（RVV256→RVV1024） | `simulated_cpu_state_riscv64_rvv_256_riscv64_rvv_1024` | `2` |

程序级 `ret`、`jr` 和 `jalr` 的
`query_original_translated_map@plt` 调用会携带上述 profile。使用
`--state-base-mode helper` 时，状态基址 helper 也会在 `a0` 中收到对应
profile；旧标量入口仍保留旧 ABI。

## 文档导航

长期设计、当前支持矩阵、状态 ABI、内部 CFG/vtype 分析和验证分层统一见 [`docs/README.md`](docs/README.md)。其中支持矩阵以当前 dispatcher 注册表为准，并明确区分“已注册”“形式受限”和“目标机语义已验证”；本 README 中的指令列表只作为快速入门。

## 命令行用法

### 标量模式

```bash
# 文件输入（完整函数输出）
python3 rvv_sbt.py input.s -o output.s

# 内联指令 + 状态播种 + 纯翻译块（-c + --init-vtype + --raw）
python3 rvv_sbt.py -c "vfmacc.vf v8, fa0, v16" --init-vtype 'sew=32,lmul=2' --raw

# 精简模式（--text-only，保留标签但去包装字段）
python3 rvv_sbt.py input.s -o output.s --text-only
```

### 256-bit RVV 模式

```bash
# 内联指令
python3 rvv_sbt_rvv.py -c "vfmacc.vf v8, fa0, v16" --init-vtype 'sew=64,lmul=1' --raw

# 文件输入
python3 rvv_sbt_rvv.py input.s -o output.s

# 完整 objdump 程序；各轮汇编直接写入文件
python3 rvv_sbt_rvv.py cc1.dump cc1_vlen1024_to_vlen256 -o translated.S

# 默认即使用宽 LMUL 热点路径；需要旧保守路径时显式传参
python3 rvv_sbt_rvv.py -c "vadd.vv v8, v16, v24" \
  --init-vtype 'sew=32,lmul=8' --raw --conservative
```

### RVV1024 过渡实验模式

`rvv_sbt_rvv1024.py` 面向迁移实验：源状态是 RVV256 紧凑布局（`source_vlenb=32`），目标硬件必须是 VLEN=1024（`target_vlenb=128`）。它使用独立的 `state_view` 和 CFG/vtype preflight，不应与 RVV256 后端的 128B 模拟 vreg 槽位解释混用。对于“已知 vtype + unknown”混合候选，程序模式默认读取源状态的 `vtype` 并分派到已知候选，未命中时执行 `ebreak`；unknown-only、未注册 opcode 和未验证 form 也会保留诊断并生成 `ebreak`。无效初始 vtype、方向几何或函数分析缺失等不可恢复的输入错误仍会拒绝。

```bash
python3 rvv_sbt_rvv1024.py input.s -o output.s
python3 rvv_sbt_rvv1024.py -c "vadd.vv v8, v16, v24" \
  --init-vtype 'sew=32,lmul=1' --raw

# 程序模式默认启用运行时 vtype 分派；未匹配候选执行 ebreak
python3 rvv_sbt_rvv1024.py input.s lib_name -o output.s
```

该模式仍是实验路径，目标机门禁和 reference/candidate 差分见 [`verify/README.md`](verify/README.md)。

### 通用参数

| 参数 | 说明 |
|------|------|
| `input` | 输入汇编文件（与 `-c` 二选一） |
| `-c`, `--command` | 内联指令字符串，如 `"vfmacc.vf v8, fa0, v16"` |
| `-o`, `--output` | 输出文件，默认 stdout |
| `--vlenb` | VLEN/8，默认 `128`（VLEN=1024）。RVV256 路径只接受 `128`：翻译方向经 `src/riscv/extensions/rvv/runtime/geometry.py` 白名单校验，未登记方向（如 64/256）会在 profile 构造期直接拒绝，不会静默生成代码 |
| `--text-only` | 去掉 `.globl`/`.type`/`.size`/`.comm`/`.text`，仅保留标签和指令正文 |
| `--raw` | 纯翻译块输出：仅状态基址装载 + handler 代码，无函数标签/ret/`.comm` |
| `--init-vtype` | 为 StateTracker 播种 SEW/LMUL/VTA/VMA，**不产生输出代码** |
| `--func-name` | 自定义输出函数名，默认 `translated_func` |
| `--state-base-mode` | `initial-exec`（默认、无函数调用）或 `helper`（兼容回退） |
| `--conservative` | 仅 RVV256：显式使用原有 m1/m2、v24-v31 保守 profile |

### `--init-vtype` 格式

仅更新 Python 内部状态，不向 `simulated_cpu_state` 写入任何内容：

```bash
# 语义形式（sew 和 lmul 必填，ta/tu/ma/mu 可选）
--init-vtype 'sew=32,lmul=2,ta,ma'

# 原始 vtype CSR 数值
--init-vtype 0xDA
```

如果输入中已有 `vsetvli`/`vsetivli`，它们会在翻译循环中自然覆盖此初始值。

### `--raw` vs `--text-only` vs 默认模式

| 输出内容 | 默认 | `--text-only` | `--raw` |
|----------|:---:|:---:|:---:|
| `.text` 段指令 | ✅ | — | — |
| `.globl`/`.type` | ✅ | — | — |
| 函数标签 `func:` | ✅ | ✅ | — |
| 翻译块（状态基址装载 + handler） | ✅ | ✅ | ✅ |
| `ret` | ✅ | ✅ | — |
| `.size`/`.comm` | ✅ | — | — |

## Python API

```python
# 标量模式
from rvv_sbt import translate_function
output = translate_function(insn_list, func_name="my_func",
                            vlenb=128, text_only=False,
                            init_vtype="sew=32,lmul=2", raw=False)

# 256-bit 模式
from rvv_sbt_rvv import translate
output = translate(insn_list, init_vtype='sew=64,lmul=1', raw=True,
                   wide_lmul=True)
```

完整程序的 `rvv_sbt_rvv.py ... lib_name -o ...` 路径按函数写出探测汇编，
完成默认的对象级跳转范围检查后再写入最终输出。大型输入应将 `TMPDIR`
设为有足够空间的磁盘目录；位于 tmpfs 的临时汇编和对象也会占用内存预算。

大型程序按完整函数分组，每组约 65536 条源指令，发射到独立的同名 `.text`
节，降低 GNU as 对单个巨型节排序重定位的开销。范围检查调用编译器的
`-nostdlib -r` 流程，先合并这些代码节，再检查统一地址下的跳转距离；因此
所选编译器需要配套的 RISC-V 链接器。探测轮和正式输出轮均保留对象检查。
`--text-only` 输出仍由调用方管理代码节。
更新翻译结果时，应一并重新生成译后 `.so` 和 offset-map，以使用最终链接后的实际地址。

文件 CLI 先完成一次全程序分析，再把函数及其 CFG/vtype 结果写入内部临时存储。
各轮发射只加载当前函数，汇编器运行期间不再持有整份 Python IR。
Python 调用方可使用 `translate_file_with_jal_range_fixup(input_path, output_path=path)`
获得同样的资源生命周期。临时记录只在本次调用内使用，不是可接收外部输入的缓存格式。

已有 `RVProgram` 的调用方仍可使用
`translate_program_with_jal_range_fixup(..., output_path=path)`，其输入对象由调用方持有。
这两个入口传入 `output_path` 时返回 `(None, fixed_sites)`；不传时返回完整汇编字符串。
`AsmParser()` 默认保留原始行，调用者可用 `retain_raw_lines=False` 省去这些
调试文本；程序 CLI 已采用该设置，原指令地址、操作数、原偏移标签和 Runtime ABI
保持不变。

CFG 保存显式控制转移和基本块出口，块内顺序边通过 `edges_for_source()` 或
`successors_for()` 查询。`FunctionAnalysis.instructions` 只保存 RVV 指令的
vtype 结果；标量常量传播及所有函数的调用摘要仍参与分析。

### RVV256 宽 LMUL 模式

默认宽 LMUL profile 不改变 `simulated_cpu_state` ABI，也不跨源指令缓存状态。每条
源 RVV 指令仍从状态块加载并在结束前写回；优化只扩大单次目标 RVV 操作使用
的临时物理寄存器组，并把 scalar tail（标量尾部）改成动态 VL 的 RVV 尾部。

目标 LMUL 使用饱和映射，放大倍数来自方向几何（`TranslationGeometry.ratio`
= 源 VLENB / 目标 VLENB = 4），不是内联常量：

```text
target_lmul = min(ratio * source_data_emul, m8)
```

同宽算术的 `source_data_emul` 等于源 LMUL；访存还需乘 `EEW/source_SEW`。
当前宽白名单为 `vfmacc.vf/vv`、`vfmul.vf`、`vfnmsac.vf`、`vadd.vv`、
unit/strided `vle/vse`、`vsse32.v` 和 `vsse64.v`，以及已注册的
whole-register move/load/store。前两类逐元素指令同时支持显式 `v0.t`：每个
宽块用 `vlm.v` 从状态块装入 bit-packed mask，masked load/算术使用 `mu`
保留未命中目标元素，随后仍完整写回状态槽。其他形态稳定回退旧 handler。

无掩码 `vfwmacc.vv` 使用异构 EEW 宽规划：旧累加器与两个窄输入均先加载，
仅写回当前块的活动元素；分数 LMUL、动态 VL 尾部和合法源/目的重叠保持原语义。
以上优化及无掩码 e16/m1 `vmacc.vx`、`vwmacc.vv`，和 e32/m8 `vfmacc.vv`、
`vle32.v` 的已验收实现属于正式主路径，`--conservative` 也使用相同实现。
被替代的 `vfwmacc.vv` 小块与标量尾部实现已删除。反向按指令形态直接使用
活动元素提交、CSR 同步与 GPR 优化，继续保持逐条 1:N 和即时状态提交。
双向真实热点分析、硬件完整状态差分与性能结果见
[`verify/rvv_bidirectional_hotspots/`](verify/rvv_bidirectional_hotspots/README.md)。
主 GEMM 四形状的六批验收见
[`verify/rvv_q3_gemm/`](verify/rvv_q3_gemm/README.md)。

宽路径使用 `v8-v31` 作为块内临时物理 vreg，`v0` 保留。该模式只有在
目标 VLEN=256 且迁移机制确认以已直写的 `simulated_cpu_state` 为权威时才
能部署；本地 pytest 只验证规划和生成合同，不能替代目标汇编、机器语义和
双向迁移验证。

## 运行测试

```bash
python3 -m pytest tests -q            # 推荐：完整结构/流程回归

# 单文件测试（pytest 模块无 __main__ 驱动，不能用 python3 直接执行）
python3 -m pytest tests/test_integration.py -q   # 标量模式集成测试
python3 -m pytest tests/test_rvv256.py -q        # 256-bit 模式单元测试
python3 -m pytest tests/test_rvv_state.py -q    # StateTracker / SimulatedStateLayout
python3 -m pytest tests/test_init_vtype.py -q    # --init-vtype 参数测试

# 方向几何与共享 vtype 解码的单一权威合同
python3 -m pytest tests/test_geometry.py tests/test_vtype_decode.py -q

# 后端工程质量门禁（几何字面量内联、bare/broad except、延迟 import backends 等）
python3 tools/check_backend_quality.py
```

## 已实现的 RVV 指令

### 标量模式

| 类别 | 指令 | 备注 |
|------|------|------|
| 配置 | `vsetvli`, `vsetivli` | |
| 算术 | `vfmacc.vf`, `vfmacc.vv`, `vfnmsac.vf` | |
| | `vfmul.vf`, `vadd.vv`, `vadd.vi`, `vadd.vx` | |
| | `vfwmacc.vv` | 仅 `e32→e64` |
| | `vfredusum.vs` | |
| | `vid.v`, `vfncvt.f.xu.w` | 仅 `e64→e32` |
| 数据移动 | `vfmv.v.f`, `vfmv.f.s`, `vmv.v.i`, `vmv.v.x`, `vmv.s.x`, `vmv4r.v` | |
| 内存 | `vle64.v`, `vle32.v`, `vse64.v`, `vse32.v` | |
| | `vlse64.v`, `vlse32.v`, `vsse64.v`, `vsse32.v` | 含 strided |
| | `vlseg2e32/64.v`, `vsseg2e32/64.v` 及 strided 变体 | |

### 256-bit RVV 模式

| 类别 | 指令 |
|------|------|
| 配置 | `vsetvli`, `vsetivli`, `vsetvl` |
| 算术 | `vfmacc.vf`, `vfmacc.vv`, `vfmadd.vv`, `vfmsub.vv`, `vfmsac.vv`, `vfnmsac.vf`, `vfmul.vf`, `vfmul.vv` |
| | `vadd.vv`, `vadd.vi`, `vadd.vx`, `vsub.vv`, `vsub.vx`, `vfadd.vv`, `vfadd.vf`, `vfsub.vv`, `vfsub.vf`, `vfrsub.vf`, `vfdiv.vv`, `vfmax.vv`, `vfmin.vv` |
| | `vfwmacc.vv`, `vfredusum.vs`, `vfredmax.vs`, `vfredmin.vs`, `vfwredosum.vs`, `vfwredusum.vs` |
| | `vfabs.v`, `vfneg.v` |
| 整数 | `vxor.vv`, `vand.vv`, `vand.vi`, `vand.vx`, `vandn.vv`, `vor.vv`, `vor.vi`, `vor.vx`, `vnot.v`, `vmax.vv`, `vmaxu.vv`, `vsll.vv`, `vsll.vx`, `vsll.vi`, `vsrl.vx`, `vsrl.vi`, `vsra.vi`, `vnsrl.wi`, `vnsra.wi`, `vnclip.wi`, `vmul.vv`, `vmadd.vv`, `vmacc.vx`, `vmul.vx`, `vrsub.vi`, `vredsum.vs`, `vredor.vs`, `vredmaxu.vs` |
| | `vwmul.vx`, `vwmul.vv`, `vwmacc.vx`, `vwmacc.vv`, `vwsll.vi`, `vwaddu.wv`, `vwredsum.vs` |
| 数据移动 | `vfmv.v.f`, `vfmv.f.s`, `vfmv.s.f`, `vmv.v.i`, `vmv.v.x`, `vmv.s.x`, `vmv.x.s` |
| | `vid.v`, `vmv1r.v`, `vmv2r.v`, `vslidedown.vi`, `vrgather.vv`, `vrgatherei16.vv` |
| 转换 | `vfncvt.f.xu.w`, `vfcvt.f.x.v`, `vfcvt.x.f.v`, `vfcvt.f.xu.v`, `vfncvt.f.f.w`, `vfncvt.x.f.w` |
| | `vfwcvt.f.f.v`, `vfwcvt.f.x.v`, `vwcvtu.x.x.v`, `vncvt.x.x.w`, `vzext.vf2`, `vzext.vf4`, `vzext.vf8`, `vsext.vf2`, `vsext.vf4` |
| 内存 | `vle64.v`, `vle32.v`, `vle16.v`, `vle8.v`, `vlse64.v`, `vlse32.v`, `vlse16.v`, `vsse64.v`, `vsse32.v` |
| | `vse64.v`, `vse32.v`, `vse16.v`, `vse8.v`, `vluxei64.v`, `vle8ff.v`, `vlseg2e32.v`, `vlseg2e64.v` |
| | `vsseg2e32.v`, `vsseg2e64.v`, `vlsseg2e32.v`, `vlsseg2e64.v`, `vssseg2e32.v`, `vssseg2e64.v` |
| | `vl1r.v`, `vl1re16.v`, `vl1re64.v`, `vs1r.v`, `vs2r.v`, `vs4r.v`, `vs8r.v`, `vl4r.v` |
| Mask | `vlm.v`, `vmsne.vv`, `vmsne.vi`, `vmseq.vi`, `vmsle.vi`, `vmsleu.vi`, `vmsgtu.vi`, `vmsleu.vv`, `vmsltu.vv`, `vmor.mm` |
| | `vfirst.m`, `vmerge.vvm`, `vmerge.vxm`, `vmerge.vim`, `vmfgt.vf`, `vmfle.vf`, `vcpop.m` |

这里的指令列表是历史性的快速索引，不应当作当前覆盖率统计。当前 dispatcher 注册集合和各模式限制见 [`docs/SUPPORTED_INSTRUCTIONS.md`](docs/SUPPORTED_INSTRUCTIONS.md)。

正向 `vle8ff.v` 使用32字节分块实现，在合法源 VL 范围内循环处理大 VL。
限制：后续 chunk 的首元素 fault 会被目标硬件视为首元素异常，不能完整复现
源指令的 fault-only-first 边界语义。入口执行源 `vstart=0` 和输入合法性检查。

程序模式的无链接间接跳转保留完整源寄存器；精确 trap PC 和 no-link ABI表由配对Runtime分派，缺少匹配条目时安全拒绝。当前实现和状态约束见 [Runtime ABI](../../../docs/developer/abi/runtime-v1.md)、[自动迁移状态机](../../../docs/architecture/automigration.md) 与 [状态 ABI](docs/STATE_ABI.md)。仅生成trap不能视为迁移成功。

三个后端都执行声明的 `VStartPolicy`：`REQUIRE_ZERO` 在数据访存及提交前
拒绝非零源 `vstart`，CSR/config 可以清零恢复；正向 `vmacc.vx` 保留已实现的
架构重启语义。拒绝不等同于 Runtime 恢复或所有指令均支持非零重启。

### Mask 支持

非 RVV256 backend 的显式 `v0.t` masked form 支持范围：`vfmacc.vf`, `vfnmsac.vf`, `vfmacc.vv`, `vfwmacc.vv`, `vfmul.vf`, `vadd.vv`, `vfredusum.vs`, `vle32/64.v`, `vse32/64.v`, `vlse32/64.v`, `vsse32/64.v`, `vlseg2e*`, `vsseg2e*` 及 strided 变体。

256-bit 模式下已支持的真 mask 指令按 RVV 1.0 bit-packed mask layout 读写 `simulated_cpu_state`：`vlm.v`, `vmsne.vv`, `vmsne.vi`, `vmseq.vi`, `vmsle.vi`, `vmsleu.vi`, `vmsgtu.vi`, `vmsleu.vv`, `vmsltu.vv`, `vmor.mm`, `vfirst.m`, `vmerge.vvm`, `vmerge.vxm`, `vmerge.vim`, `vmfgt.vf`, `vmfle.vf`, `vcpop.m`。其他 `..., v0.t` masked form 当前会 fail-fast，避免被静默当成 unmasked 翻译；仍未覆盖的 mask 指令包括 `vmand.*`, `vcompress.*` 等。

默认宽 profile 额外覆盖 `vadd.vv`、`vfmacc.vf/vv`、
`vfmul.vf`、`vfnmsac.vf` 以及已支持 unit/strided load/store 的 `v0.t` 形式。
非 `v0.t` 的 mask operand 会直接生成 `ebreak`，不会偷换为模拟 `v0`。

## 关键设计约束

- 翻译方向几何（源/目标 VLENB、比值、块元素数、整寄存器搬运宽度）唯一权威是 `src/riscv/extensions/rvv/runtime/geometry.py`；已登记方向仅 `128→32` 与 `32→128`，非法 `--vlenb` 在 profile 构造期 fail-fast
- LMUL 合法集/token 表位于 `src/riscv/extensions/rvv/analysis/model.py`（`LEGAL_LMULS`/`LMUL_TOKENS`）；运行时 vtype 解码（含 vill、`vtype[62:8]` 保留位、保留 `vlmul=100` 检查）统一在 `src/riscv/extensions/rvv/translation/vtype_decode.py`；状态基址标记 `CHIMERA_STATE_BASE` 只在 `src/riscv/extensions/rvv/runtime/access.py` 定义——后端不得内联这些字面量，`tools/check_backend_quality.py` 强制
- 1024→256 状态块中 v0-v31 各 128B（0x000-0xF80）；256→1024 状态块中源 vN 位于 N*32B；两者 CSR 均位于 0x1000-0x1030
- `t6` 在每个翻译块内重载为当前契约指定的状态基址。默认使用 `la.tls.ie` + `add t6, t6, tp`，避免旧 helper 调用导致的全 caller-saved GPR/FPR 保存
- **块级 save/restore**，非函数级栈帧——避免破坏原始标量代码中的 `sp` 相对寻址
- 默认 Initial-Exec TLS 要求 `libinject.so` 通过 `LD_PRELOAD` 在启动期加载；翻译库仍由 `dlopen` 装入，必须先在目标动态加载器验证 IE 重定位/加载，门禁失败时显式使用 `--state-base-mode helper`
- 每条源 RVV 指令结束时继续 write-through（直写）到 `simulated_cpu_state`；每个源地址均可能是迁移入口，禁止在没有新安全点/flush 合同的情况下跨指令延迟写回
- `vl` 从 CSR 内存（0x1020）运行时读取，不做静态写死
- `--init-vtype` 仅播种 StateTracker，不产生输出代码
- `--conservative` 路径按 m1 strip-mining；无掩码热点已把固定 vset 外提到循环外
- 默认宽 profile 采用饱和目标 LMUL、固定完整块和单个动态 VL 向量尾部；白名单中的 `v0.t` 形式使用 `vlm.v` + `mu`
- 宽路径只在单条源指令内使用 v8-v31（`WideVRegGroupAllocator` 与保守池同样记录 clobber）；不允许跨 `branch_j_target` 保留 dirty vreg
- ebreak fallback 文案由后端 `fallback_result()` 品牌化生产（正向输出 `RVV256 fallback`，反向过渡输出 `RVV1024 fallback`），core 仅保留通用模板兜底
- 标量输出限 RV64G（无 Zbb，无 RVV）
