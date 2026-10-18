<!-- 此文件由 tools/generate_support_docs.py 生成，请勿手工编辑。 -->
# 后端注册能力

本文件只描述当前 `InstructionSpec` registry 中的**已注册能力与结构限制**。
它不是目标机语义验证报告；注册、生成汇编和目标机差分验证仍是不同层级。

重新生成：

```bash
python3 tools/generate_support_docs.py
python3 tools/generate_support_docs.py --check
```

| 后端/profile | 注册数 | fallback | 说明 |
|---|---:|---|---|
| 标量 RV64 | 65 | 抛出异常，CLI 失败 | `rvv_sbt.py` |
| RVV256 宽 profile | 199 | 诊断 + `ebreak` | `rvv_sbt_rvv.py` 默认 |
| RVV256 保守 profile | 199 | 诊断 + `ebreak` | `rvv_sbt_rvv.py --conservative` |
| RVV256→RVV1024 过渡 | 205 | 诊断 + `ebreak` | `rvv_sbt_rvv1024.py` |

## 标量 RV64 后端

逐元素在 RV64 上执行；未注册 opcode 通过公共 `UnsupportedInstructionError` 失败。

注册总数：**65**。分类计数：arithmetic=31, config=3, csr=13, memory-load=10, memory-store=8。

### `arithmetic`（31）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vadd.vi` | `vd, vs2, simm5` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `scalar-sequence` | `modular-integer` | `exact-integer` |
| `vadd.vv` | `vd, vs2, vs1` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `scalar-sequence` | `modular-integer` | `exact-integer` |
| `vadd.vx` | `vd, vs2, rs1` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `scalar-sequence` | `modular-integer` | `exact-integer` |
| `vand.vi` | `vd, vs2, simm5` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `scalar-sequence` | `bit-preserving` | `exact-integer` |
| `vfcvt.f.x.v` | `vd, signed vs2` | e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `scalar-sequence` | `signed-integer-to-floating-point` | `architectural-frm` |
| `vfmacc.vf` | `vd, rs1, vs2` | e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `scalar-sequence` | `floating-point` | `architectural-frm` |
| `vfmacc.vv` | `vd, vs1, vs2` | e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `scalar-sequence` | `floating-point` | `architectural-frm` |
| `vfmul.vf` | `vd, vs2, fp-rs1` | e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `scalar-sequence` | `floating-point` | `architectural-frm` |
| `vfmv.f.s` | `fp-rd, vs2` | e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `scalar-sequence` | `floating-point` | `not-applicable` |
| `vfmv.v.f` | `vd, fp-rs1` | e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `scalar-sequence` | `floating-point` | `not-applicable` |
| `vfncvt.f.xu.w` | `narrow vd, wide unsigned vs2` | e32 | mf8/mf4/mf2/m1/m2/m4 | `v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `scalar-sequence` | `unsigned-integer-to-floating-point` | `architectural-frm` |
| `vfnmsac.vf` | `vd, rs1, vs2` | e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `scalar-sequence` | `floating-point` | `architectural-frm` |
| `vfredusum.vs` | `vd(m1), vs2(LMUL), vs1(m1)` | e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `scalar-sequence` | `floating-point` | `architectural-frm` |
| `vfwcvt.f.f.v` | `wide vd, narrow vs2` | e16/e32 | mf8/mf4/mf2/m1/m2/m4 | `v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `scalar-sequence` | `floating-point` | `architectural-frm` |
| `vfwmacc.vv` | `wide vd, narrow vs1, narrow vs2` | e32 | mf8/mf4/mf2/m1/m2/m4 | `v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `scalar-sequence` | `floating-point` | `architectural-frm` |
| `vid.v` | `vd` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `scalar-sequence` | `unsigned-index` | `exact-integer` |
| `vmacc.vx` | `vd, rs1, vs2` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `scalar-sequence` | `modular-integer` | `exact-integer` |
| `vmseq.vi` | `mask vd, vs2, simm5` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `scalar-sequence` | `equality-compare` | `exact-integer` |
| `vmv.s.x` | `vd, rs1` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `scalar-sequence` | `bit-preserving` | `exact-integer` |
| `vmv.v.i` | `vd, simm5` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `scalar-sequence` | `bit-preserving` | `exact-integer` |
| `vmv.v.x` | `vd, rs1` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `scalar-sequence` | `bit-preserving` | `exact-integer` |
| `vmv1r.v` | `raw vd, raw vs2` | 指令内决定/不依赖 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 是 | `scalar-sequence` | `bit-preserving` | `not-applicable` |
| `vmv2r.v` | `raw vd, raw vs2` | 指令内决定/不依赖 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 是 | `scalar-sequence` | `bit-preserving` | `not-applicable` |
| `vmv4r.v` | `raw vd, raw vs2` | 指令内决定/不依赖 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 是 | `scalar-sequence` | `bit-preserving` | `not-applicable` |
| `vor.vv` | `vd, vs2, vs1` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `scalar-sequence` | `bit-preserving` | `exact-integer` |
| `vsll.vi` | `vd, vs2, uimm5` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `scalar-sequence` | `logical-shift` | `exact-integer` |
| `vsrl.vi` | `vd, vs2, uimm5` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `scalar-sequence` | `logical-shift` | `exact-integer` |
| `vsrl.vx` | `vd, vs2, rs1` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `scalar-sequence` | `logical-shift` | `exact-integer` |
| `vsub.vx` | `vd, vs2, rs1` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `scalar-sequence` | `modular-integer` | `exact-integer` |
| `vwmacc.vv` | `wide vd, narrow vs1, narrow vs2` | e8/e16/e32 | mf8/mf4/mf2/m1/m2/m4 | `v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `scalar-sequence` | `signed-widen-multiply` | `exact-integer` |
| `vzext.vf2` | `vd, half-width vs2` | e16/e32/e64 | mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `scalar-sequence` | `zero-extension` | `exact-integer` |

### `config`（3）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vsetivli` | `rd, uimm5, eSEW, LMUL, tail, mask` | 指令内决定/不依赖 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `not-applicable` | 否 | 否 | `scalar-sequence` | `not-applicable` | `not-applicable` |
| `vsetvl` | `rd, rs1, rs2` | 指令内决定/不依赖 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `not-applicable` | 否 | 否 | `scalar-sequence` | `not-applicable` | `not-applicable` |
| `vsetvli` | `rd, rs1, eSEW, LMUL, tail, mask` | 指令内决定/不依赖 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `not-applicable` | 否 | 否 | `scalar-sequence` | `not-applicable` | `not-applicable` |

### `csr`（13）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `csrc` | `vector-csr, rs1` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `not-applicable` | 否 | 是 | `scalar-sequence` | `raw-csr-value` | `not-applicable` |
| `csrci` | `vector-csr, zimm` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `not-applicable` | 否 | 是 | `scalar-sequence` | `raw-csr-value` | `not-applicable` |
| `csrr` | `rd, vector-csr` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `not-applicable` | 否 | 是 | `scalar-sequence` | `raw-csr-value` | `not-applicable` |
| `csrrc` | `rd, vector-csr, rs1` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `not-applicable` | 否 | 是 | `scalar-sequence` | `raw-csr-value` | `not-applicable` |
| `csrrci` | `rd, vector-csr, zimm` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `not-applicable` | 否 | 是 | `scalar-sequence` | `raw-csr-value` | `not-applicable` |
| `csrrs` | `rd, vector-csr, rs1` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `not-applicable` | 否 | 是 | `scalar-sequence` | `raw-csr-value` | `not-applicable` |
| `csrrsi` | `rd, vector-csr, zimm` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `not-applicable` | 否 | 是 | `scalar-sequence` | `raw-csr-value` | `not-applicable` |
| `csrrw` | `rd, vector-csr, rs1` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `not-applicable` | 否 | 是 | `scalar-sequence` | `raw-csr-value` | `not-applicable` |
| `csrrwi` | `rd, vector-csr, zimm` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `not-applicable` | 否 | 是 | `scalar-sequence` | `raw-csr-value` | `not-applicable` |
| `csrs` | `vector-csr, rs1` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `not-applicable` | 否 | 是 | `scalar-sequence` | `raw-csr-value` | `not-applicable` |
| `csrsi` | `vector-csr, zimm` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `not-applicable` | 否 | 是 | `scalar-sequence` | `raw-csr-value` | `not-applicable` |
| `csrw` | `vector-csr, rs1` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `not-applicable` | 否 | 是 | `scalar-sequence` | `raw-csr-value` | `not-applicable` |
| `csrwi` | `vector-csr, zimm` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `not-applicable` | 否 | 是 | `scalar-sequence` | `raw-csr-value` | `not-applicable` |

### `memory-load`（10）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vle16.v` | `vd, (rs1)` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `scalar-sequence` | `not-applicable` | `not-applicable` |
| `vle32.v` | `vd, (rs1)` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `scalar-sequence` | `not-applicable` | `not-applicable` |
| `vle64.v` | `vd, (rs1)` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `scalar-sequence` | `not-applicable` | `not-applicable` |
| `vle8.v` | `vd, (rs1)` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `scalar-sequence` | `not-applicable` | `not-applicable` |
| `vlse32.v` | `vd, (rs1), rs2` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `scalar-sequence` | `signed-byte-stride` | `not-applicable` |
| `vlse64.v` | `vd, (rs1), rs2` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `scalar-sequence` | `signed-byte-stride` | `not-applicable` |
| `vlseg2e32.v` | `tuple vd, (rs1)` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `scalar-sequence` | `not-applicable` | `not-applicable` |
| `vlseg2e64.v` | `tuple vd, (rs1)` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `scalar-sequence` | `not-applicable` | `not-applicable` |
| `vlsseg2e32.v` | `tuple vd, (rs1), rs2` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `scalar-sequence` | `signed-byte-stride` | `not-applicable` |
| `vlsseg2e64.v` | `tuple vd, (rs1), rs2` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `scalar-sequence` | `signed-byte-stride` | `not-applicable` |

### `memory-store`（8）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vse32.v` | `vs3, (rs1)` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `not-applicable` | `require-zero` | 是 | 否 | `scalar-sequence` | `not-applicable` | `not-applicable` |
| `vse64.v` | `vs3, (rs1)` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `not-applicable` | `require-zero` | 是 | 否 | `scalar-sequence` | `not-applicable` | `not-applicable` |
| `vsse32.v` | `vs3, (rs1), rs2` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `not-applicable` | `require-zero` | 是 | 否 | `scalar-sequence` | `signed-byte-stride` | `not-applicable` |
| `vsse64.v` | `vs3, (rs1), rs2` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `not-applicable` | `require-zero` | 是 | 否 | `scalar-sequence` | `signed-byte-stride` | `not-applicable` |
| `vsseg2e32.v` | `tuple vs3, (rs1)` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `not-applicable` | `require-zero` | 是 | 否 | `scalar-sequence` | `not-applicable` | `not-applicable` |
| `vsseg2e64.v` | `tuple vs3, (rs1)` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `not-applicable` | `require-zero` | 是 | 否 | `scalar-sequence` | `not-applicable` | `not-applicable` |
| `vssseg2e32.v` | `tuple vs3, (rs1), rs2` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `not-applicable` | `require-zero` | 是 | 否 | `scalar-sequence` | `signed-byte-stride` | `not-applicable` |
| `vssseg2e64.v` | `tuple vs3, (rs1), rs2` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `not-applicable` | `require-zero` | 是 | 否 | `scalar-sequence` | `signed-byte-stride` | `not-applicable` |

## RVV256 后端

源语义 VLEN=1024，目标 VLEN=256。表中 mask 按“默认宽 profile / `--conservative`”排列；具体寄存器组形状仍由纯 validator 与 planner 检查。`vle8ff.v` 使用单次目标操作，在合法源状态下仅支持 `VL <= min(VLMAX, 256)`；超容量在 guest 访存前拒绝。运行期限制与审查修复状态见 `CODE_REVIEW_MERGED.md`。

注册总数：**199**。分类计数：arithmetic=4, config=3, csr=13, fixed-point-narrow=3, float-convert=3, float-convert-narrow=3, float-convert-widen=2, float-fused=7, float-move=3, float-reduction=3, float-reduction-widen=2, float-same-width=10, float-unary=2, float-widen=1, float-widen-fused=1, gather=2, integer-accumulate=4, integer-convert=3, integer-extend=5, integer-index=1, integer-move=5, integer-reduction=3, integer-same-width=26, integer-unary=1, integer-widen=5, integer-widen-accumulate=2, integer-widen-multiply=5, integer-widen-reduction=1, mask-compare=14, mask-load=1, mask-logic=4, mask-merge=3, mask-scan=2, memory=44, slide=5, whole-register=3。

### `arithmetic`（4）

| opcode | 合法 operand form | SEW | LMUL | mask（宽/保守） | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vmv1r.v` | `vd, vs2` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden / forbidden` | `not-applicable` | `require-zero` | 否 | 是 | `vmv1r.v` | `bit-preserving` | `not-applicable` |
| `vmv2r.v` | `vd, vs2` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden / forbidden` | `not-applicable` | `require-zero` | 否 | 是 | `vmv2r.v` | `bit-preserving` | `not-applicable` |
| `vmv4r.v` | `vd, vs2` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden / forbidden` | `not-applicable` | `require-zero` | 否 | 是 | `vmv4r.v` | `bit-preserving` | `not-applicable` |
| `vmv8r.v` | `vd, vs2` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden / forbidden` | `not-applicable` | `require-zero` | 否 | 是 | `vmv8r.v` | `bit-preserving` | `not-applicable` |

### `config`（3）

| opcode | 合法 operand form | SEW | LMUL | mask（宽/保守） | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vsetivli` | `rd, avl, eSEW, LMUL, tail, mask` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden / forbidden` | `not-applicable` | `not-applicable` | 否 | 否 | `vsetivli` | `not-applicable` | `not-applicable` |
| `vsetvl` | `rd, rs1, rs2` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden / forbidden` | `not-applicable` | `not-applicable` | 否 | 否 | `vsetvl` | `not-applicable` | `not-applicable` |
| `vsetvli` | `rd, avl, eSEW, LMUL, tail, mask` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden / forbidden` | `not-applicable` | `not-applicable` | 否 | 否 | `vsetvli` | `not-applicable` | `not-applicable` |

### `csr`（13）

| opcode | 合法 operand form | SEW | LMUL | mask（宽/保守） | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `csrc` | `vector-csr, rs1` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden / forbidden` | `not-applicable` | `not-applicable` | 否 | 是 | `csrc` | `raw-csr-value` | `not-applicable` |
| `csrci` | `vector-csr, zimm` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden / forbidden` | `not-applicable` | `not-applicable` | 否 | 是 | `csrci` | `raw-csr-value` | `not-applicable` |
| `csrr` | `rd, vector-csr` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden / forbidden` | `not-applicable` | `not-applicable` | 否 | 是 | `csrr` | `raw-csr-value` | `not-applicable` |
| `csrrc` | `rd, vector-csr, rs1` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden / forbidden` | `not-applicable` | `not-applicable` | 否 | 是 | `csrrc` | `raw-csr-value` | `not-applicable` |
| `csrrci` | `rd, vector-csr, zimm` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden / forbidden` | `not-applicable` | `not-applicable` | 否 | 是 | `csrrci` | `raw-csr-value` | `not-applicable` |
| `csrrs` | `rd, vector-csr, rs1` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden / forbidden` | `not-applicable` | `not-applicable` | 否 | 是 | `csrrs` | `raw-csr-value` | `not-applicable` |
| `csrrsi` | `rd, vector-csr, zimm` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden / forbidden` | `not-applicable` | `not-applicable` | 否 | 是 | `csrrsi` | `raw-csr-value` | `not-applicable` |
| `csrrw` | `rd, vector-csr, rs1` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden / forbidden` | `not-applicable` | `not-applicable` | 否 | 是 | `csrrw` | `raw-csr-value` | `not-applicable` |
| `csrrwi` | `rd, vector-csr, zimm` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden / forbidden` | `not-applicable` | `not-applicable` | 否 | 是 | `csrrwi` | `raw-csr-value` | `not-applicable` |
| `csrs` | `vector-csr, rs1` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden / forbidden` | `not-applicable` | `not-applicable` | 否 | 是 | `csrs` | `raw-csr-value` | `not-applicable` |
| `csrsi` | `vector-csr, zimm` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden / forbidden` | `not-applicable` | `not-applicable` | 否 | 是 | `csrsi` | `raw-csr-value` | `not-applicable` |
| `csrw` | `vector-csr, rs1` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden / forbidden` | `not-applicable` | `not-applicable` | 否 | 是 | `csrw` | `raw-csr-value` | `not-applicable` |
| `csrwi` | `vector-csr, zimm` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden / forbidden` | `not-applicable` | `not-applicable` | 否 | 是 | `csrwi` | `raw-csr-value` | `not-applicable` |

### `fixed-point-narrow`（3）

| opcode | 合法 operand form | SEW | LMUL | mask（宽/保守） | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vnclip.wi` | `narrow vd, wide vs2, uimm` | e8/e16/e32 | mf8/mf4/mf2/m1/m2/m4 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vnclip.wi` | `signed-fixed-point` | `vxrm-for-vnclip` |
| `vnsra.wi` | `narrow vd, wide vs2, uimm` | e8/e16/e32 | mf8/mf4/mf2/m1/m2/m4 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vnsra.wi` | `arithmetic-shift` | `vxrm-for-vnclip` |
| `vnsrl.wi` | `narrow vd, wide vs2, uimm[, v0.t]`<br>`narrow vd, wide vs2, uimm[, v0.t], v0.t` | e8/e16/e32 | mf8/mf4/mf2/m1/m2/m4 | `v0-only / v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `vnsrl.wi` | `logical-shift` | `vxrm-for-vnclip` |

### `float-convert`（3）

| opcode | 合法 operand form | SEW | LMUL | mask（宽/保守） | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vfcvt.f.x.v` | `vd, vs2` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vfcvt.f.x.v` | `signed-integer-to-floating-point` | `dynamic-frm` |
| `vfcvt.f.xu.v` | `vd, vs2` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vfcvt.f.xu.v` | `unsigned-integer-to-floating-point` | `dynamic-frm` |
| `vfcvt.x.f.v` | `vd, vs2` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vfcvt.x.f.v` | `floating-point-to-signed-integer` | `dynamic-frm` |

### `float-convert-narrow`（3）

| opcode | 合法 operand form | SEW | LMUL | mask（宽/保守） | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vfncvt.f.f.w` | `narrow vd, wide vs2` | e16/e32 | mf8/mf4/mf2/m1/m2/m4 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vfncvt.f.f.w` | `floating-point` | `dynamic-frm` |
| `vfncvt.f.xu.w` | `narrow vd, wide vs2` | e16/e32 | mf8/mf4/mf2/m1/m2/m4 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vfncvt.f.xu.w` | `unsigned-integer-to-floating-point` | `dynamic-frm` |
| `vfncvt.x.f.w` | `narrow vd, wide vs2` | e16/e32 | mf8/mf4/mf2/m1/m2/m4 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vfncvt.x.f.w` | `floating-point-to-signed-integer` | `dynamic-frm` |

### `float-convert-widen`（2）

| opcode | 合法 operand form | SEW | LMUL | mask（宽/保守） | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vfwcvt.f.f.v` | `wide vd, narrow vs2` | e16/e32 | mf8/mf4/mf2/m1/m2/m4 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vfwcvt.f.f.v` | `floating-point` | `dynamic-frm` |
| `vfwcvt.f.x.v` | `wide vd, narrow vs2` | e16/e32 | mf8/mf4/mf2/m1/m2/m4 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vfwcvt.f.x.v` | `signed-integer-to-floating-point` | `dynamic-frm` |

### `float-fused`（7）

| opcode | 合法 operand form | SEW | LMUL | mask（宽/保守） | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vfmacc.vf` | `vd, rs1, vs2[, v0.t]`<br>`vd, rs1, vs2[, v0.t], v0.t` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only / v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `vfmacc.vf` | `floating` | `dynamic-frm` |
| `vfmacc.vv` | `vd, vs1, vs2[, v0.t]`<br>`vd, vs1, vs2[, v0.t], v0.t` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only / forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vfmacc.vv` | `floating` | `dynamic-frm` |
| `vfmadd.vf` | `vd, multiplicand, addend` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vfmadd.vf` | `floating` | `dynamic-frm` |
| `vfmadd.vv` | `vd, multiplicand, addend` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vfmadd.vv` | `floating` | `dynamic-frm` |
| `vfmsac.vv` | `vd, multiplicand, addend` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vfmsac.vv` | `floating` | `dynamic-frm` |
| `vfmsub.vv` | `vd, multiplicand, addend` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vfmsub.vv` | `floating` | `dynamic-frm` |
| `vfnmsac.vf` | `vd, rs1, vs2[, v0.t]`<br>`vd, rs1, vs2[, v0.t], v0.t` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only / forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vfnmsac.vf` | `floating` | `dynamic-frm` |

### `float-move`（3）

| opcode | 合法 operand form | SEW | LMUL | mask（宽/保守） | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vfmv.f.s` | `fp-rd, vs2` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `not-applicable` | `require-zero` | 否 | 否 | `vfmv.f.s` | `floating-bit-preserving` | `exact` |
| `vfmv.s.f` | `destination, source` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vfmv.s.f` | `floating-bit-preserving` | `exact` |
| `vfmv.v.f` | `destination, source` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vfmv.v.f` | `floating-bit-preserving` | `exact` |

### `float-reduction`（3）

| opcode | 合法 operand form | SEW | LMUL | mask（宽/保守） | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vfredmax.vs` | `vd, vs2, vs1` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vfredmax.vs` | `floating` | `dynamic-frm` |
| `vfredmin.vs` | `vd, vs2, vs1` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vfredmin.vs` | `floating` | `dynamic-frm` |
| `vfredusum.vs` | `vd, vs2, vs1` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vfredusum.vs` | `floating` | `dynamic-frm` |

### `float-reduction-widen`（2）

| opcode | 合法 operand form | SEW | LMUL | mask（宽/保守） | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vfwredosum.vs` | `wide vd, narrow vs2, wide vs1` | e16/e32 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vfwredosum.vs` | `floating` | `dynamic-frm` |
| `vfwredusum.vs` | `wide vd, narrow vs2, wide vs1` | e16/e32 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vfwredusum.vs` | `floating` | `dynamic-frm` |

### `float-same-width`（10）

| opcode | 合法 operand form | SEW | LMUL | mask（宽/保守） | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vfadd.vf` | `vd, vs2, rs1[, v0.t]`<br>`vd, vs2, rs1[, v0.t], v0.t` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only / v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `vfadd.vf` | `floating` | `dynamic-frm` |
| `vfadd.vv` | `vd, vs2, vs1[, v0.t]`<br>`vd, vs2, vs1[, v0.t], v0.t` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only / v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `vfadd.vv` | `floating` | `dynamic-frm` |
| `vfdiv.vv` | `vd, vs2, vs1[, v0.t]`<br>`vd, vs2, vs1[, v0.t], v0.t` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only / v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `vfdiv.vv` | `floating` | `dynamic-frm` |
| `vfmax.vv` | `vd, vs2, vs1` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vfmax.vv` | `floating` | `dynamic-frm` |
| `vfmin.vv` | `vd, vs2, vs1` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vfmin.vv` | `floating` | `dynamic-frm` |
| `vfmul.vf` | `vd, vs2, rs1[, v0.t]`<br>`vd, vs2, rs1[, v0.t], v0.t` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only / v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `vfmul.vf` | `floating` | `dynamic-frm` |
| `vfmul.vv` | `vd, vs2, vs1[, v0.t]`<br>`vd, vs2, vs1[, v0.t], v0.t` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only / v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `vfmul.vv` | `floating` | `dynamic-frm` |
| `vfrsub.vf` | `vd, vs2, rs1[, v0.t]`<br>`vd, vs2, rs1[, v0.t], v0.t` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only / v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `vfrsub.vf` | `floating` | `dynamic-frm` |
| `vfsub.vf` | `vd, vs2, rs1` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vfsub.vf` | `floating` | `dynamic-frm` |
| `vfsub.vv` | `vd, vs2, vs1[, v0.t]`<br>`vd, vs2, vs1[, v0.t], v0.t` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only / v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `vfsub.vv` | `floating` | `dynamic-frm` |

### `float-unary`（2）

| opcode | 合法 operand form | SEW | LMUL | mask（宽/保守） | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vfabs.v` | `vd, vs2` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vfabs.v` | `floating` | `exact` |
| `vfneg.v` | `vd, vs2[, v0.t]`<br>`vd, vs2[, v0.t], v0.t` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only / v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `vfneg.v` | `floating` | `exact` |

### `float-widen`（1）

| opcode | 合法 operand form | SEW | LMUL | mask（宽/保守） | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vfwmul.vf` | `wide vd, narrow vs2, narrow rs1` | e16 | m1 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vfwmul.vf` | `floating` | `dynamic-frm` |

### `float-widen-fused`（1）

| opcode | 合法 operand form | SEW | LMUL | mask（宽/保守） | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vfwmacc.vv` | `wide vd, narrow vs1, narrow vs2` | e16/e32 | mf8/mf4/mf2/m1/m2/m4 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vfwmacc.vv` | `floating` | `dynamic-frm` |

### `gather`（2）

| opcode | 合法 operand form | SEW | LMUL | mask（宽/保守） | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vrgather.vv` | `vd, vs2, index-vector` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vrgather.vv` | `unsigned-index` | `exact` |
| `vrgatherei16.vv` | `vd, vs2, index-vector` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vrgatherei16.vv` | `unsigned-index` | `exact` |

### `integer-accumulate`（4）

| opcode | 合法 operand form | SEW | LMUL | mask（宽/保守） | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vmacc.vv` | `vd, multiplicand, addend` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vmacc.vv` | `two-complement` | `exact` |
| `vmacc.vx` | `vd, multiplicand, addend` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `architectural` | 是 | 否 | `vmacc.vx` | `two-complement` | `exact` |
| `vmadd.vv` | `vd, multiplicand, addend` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vmadd.vv` | `two-complement` | `exact` |
| `vmadd.vx` | `vd, multiplicand, addend` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vmadd.vx` | `two-complement` | `exact` |

### `integer-convert`（3）

| opcode | 合法 operand form | SEW | LMUL | mask（宽/保守） | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vncvt.x.x.w` | `vd, vs2` | e8/e16/e32 | mf8/mf4/mf2/m1/m2/m4 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vncvt.x.x.w` | `signed-integer` | `exact` |
| `vwcvt.x.x.v` | `vd, vs2` | e8/e16/e32 | mf8/mf4/mf2/m1/m2/m4 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vwcvt.x.x.v` | `signed-integer` | `exact` |
| `vwcvtu.x.x.v` | `vd, vs2` | e8/e16/e32 | mf8/mf4/mf2/m1/m2/m4 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vwcvtu.x.x.v` | `unsigned-integer` | `exact` |

### `integer-extend`（5）

| opcode | 合法 operand form | SEW | LMUL | mask（宽/保守） | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vsext.vf2` | `wide vd, narrow vs2` | e16/e32/e64 | mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vsext.vf2` | `signed-extension` | `exact` |
| `vsext.vf4` | `wide vd, narrow vs2` | e32/e64 | mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vsext.vf4` | `signed-extension` | `exact` |
| `vzext.vf2` | `wide vd, narrow vs2` | e16/e32/e64 | mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vzext.vf2` | `zero-extension` | `exact` |
| `vzext.vf4` | `wide vd, narrow vs2` | e32/e64 | mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vzext.vf4` | `zero-extension` | `exact` |
| `vzext.vf8` | `wide vd, narrow vs2` | e64 | m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vzext.vf8` | `zero-extension` | `exact` |

### `integer-index`（1）

| opcode | 合法 operand form | SEW | LMUL | mask（宽/保守） | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vid.v` | `vd` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vid.v` | `unsigned-index` | `exact` |

### `integer-move`（5）

| opcode | 合法 operand form | SEW | LMUL | mask（宽/保守） | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vmv.s.x` | `destination, source` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmv.s.x` | `bit-preserving` | `exact` |
| `vmv.v.i` | `destination, source` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmv.v.i` | `bit-preserving` | `exact` |
| `vmv.v.v` | `destination, source` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmv.v.v` | `bit-preserving` | `exact` |
| `vmv.v.x` | `destination, source` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmv.v.x` | `bit-preserving` | `exact` |
| `vmv.x.s` | `rd, vs2` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `not-applicable` | `require-zero` | 否 | 否 | `vmv.x.s` | `bit-preserving` | `exact` |

### `integer-reduction`（3）

| opcode | 合法 operand form | SEW | LMUL | mask（宽/保守） | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vredmaxu.vs` | `vd, vs2, vs1` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vredmaxu.vs` | `unsigned-integer` | `exact` |
| `vredor.vs` | `vd, vs2, vs1` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vredor.vs` | `bitwise` | `exact` |
| `vredsum.vs` | `vd, vs2, vs1` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vredsum.vs` | `modular-reduction` | `exact` |

### `integer-same-width`（26）

| opcode | 合法 operand form | SEW | LMUL | mask（宽/保守） | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vadd.vi` | `vd, vs2, immediate[, v0.t]`<br>`vd, vs2, immediate[, v0.t], v0.t` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only / v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `vadd.vi` | `modular-integer` | `exact` |
| `vadd.vv` | `vd, vs2, vs1[, v0.t]`<br>`vd, vs2, vs1[, v0.t], v0.t` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only / v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `vadd.vv` | `modular-integer` | `exact` |
| `vadd.vx` | `vd, vs2, rs1[, v0.t]`<br>`vd, vs2, rs1[, v0.t], v0.t` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only / v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `vadd.vx` | `modular-integer` | `exact` |
| `vand.vi` | `vd, vs2, immediate` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vand.vi` | `bitwise` | `exact` |
| `vand.vv` | `vd, vs2, vs1` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vand.vv` | `bitwise` | `exact` |
| `vand.vx` | `vd, vs2, rs1[, v0.t]`<br>`vd, vs2, rs1[, v0.t], v0.t` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only / v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `vand.vx` | `bitwise` | `exact` |
| `vandn.vv` | `vd, vs2, vs1` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vand.vv` | `bitwise` | `exact` |
| `vdiv.vx` | `vd, vs2, rs1` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vdiv.vx` | `signed-integer` | `exact` |
| `vmax.vv` | `vd, vs2, vs1` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmax.vv` | `signed-integer` | `exact` |
| `vmaxu.vv` | `vd, vs2, vs1` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmaxu.vv` | `unsigned-integer` | `exact` |
| `vmul.vv` | `vd, vs2, vs1` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmul.vv` | `modular-integer` | `exact` |
| `vmul.vx` | `vd, vs2, rs1` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmul.vx` | `modular-integer` | `exact` |
| `vor.vi` | `vd, vs2, immediate[, v0.t]`<br>`vd, vs2, immediate[, v0.t], v0.t` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only / v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `vor.vi` | `bitwise` | `exact` |
| `vor.vv` | `vd, vs2, vs1[, v0.t]`<br>`vd, vs2, vs1[, v0.t], v0.t` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only / v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `vor.vv` | `bitwise` | `exact` |
| `vor.vx` | `vd, vs2, rs1[, v0.t]`<br>`vd, vs2, rs1[, v0.t], v0.t` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only / v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `vor.vx` | `bitwise` | `exact` |
| `vrsub.vi` | `vd, vs2, immediate[, v0.t]`<br>`vd, vs2, immediate[, v0.t], v0.t` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only / v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `vrsub.vi` | `modular-integer` | `exact` |
| `vsll.vi` | `vd, vs2, immediate[, v0.t]`<br>`vd, vs2, immediate[, v0.t], v0.t` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only / v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `vsll.vi` | `logical-shift` | `exact` |
| `vsll.vv` | `vd, vs2, vs1[, v0.t]`<br>`vd, vs2, vs1[, v0.t], v0.t` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only / v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `vsll.vv` | `logical-shift` | `exact` |
| `vsll.vx` | `vd, vs2, rs1` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vsll.vx` | `logical-shift` | `exact` |
| `vsra.vi` | `vd, vs2, immediate` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vsra.vi` | `arithmetic-shift` | `exact` |
| `vsrl.vi` | `vd, vs2, immediate` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vsrl.vi` | `logical-shift` | `exact` |
| `vsrl.vv` | `vd, vs2, vs1` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vsrl.vv` | `logical-shift` | `exact` |
| `vsrl.vx` | `vd, vs2, rs1` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vsrl.vx` | `logical-shift` | `exact` |
| `vsub.vv` | `vd, vs2, vs1` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vsub.vv` | `modular-integer` | `exact` |
| `vsub.vx` | `vd, vs2, rs1[, v0.t]`<br>`vd, vs2, rs1[, v0.t], v0.t` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only / v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `vsub.vx` | `modular-integer` | `exact` |
| `vxor.vv` | `vd, vs2, vs1` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vxor.vv` | `bitwise` | `exact` |

### `integer-unary`（1）

| opcode | 合法 operand form | SEW | LMUL | mask（宽/保守） | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vnot.v` | `vd, vs2` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vxor.vi` | `bitwise` | `exact` |

### `integer-widen`（5）

| opcode | 合法 operand form | SEW | LMUL | mask（宽/保守） | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vwadd.vv` | `wide vd, narrow/wide source, source` | e8/e16/e32 | mf8/mf4/mf2/m1/m2/m4 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vwadd.vv` | `signed-widen-add` | `exact` |
| `vwadd.wv` | `wide vd, narrow/wide source, source` | e8/e16/e32 | mf8/mf4/mf2/m1/m2/m4 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vwadd.wv` | `signed-widen-add` | `exact` |
| `vwaddu.vx` | `wide vd, narrow/wide source, source` | e8/e16/e32 | mf8/mf4/mf2/m1/m2/m4 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vwaddu.vx` | `unsigned-widen-add` | `exact` |
| `vwaddu.wv` | `wide vd, narrow/wide source, source` | e8/e16/e32 | mf8/mf4/mf2/m1/m2/m4 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vwaddu.wv` | `unsigned-widen-add` | `exact` |
| `vwsll.vi` | `wide vd, narrow/wide source, source` | e8/e16/e32 | mf8/mf4/mf2/m1/m2/m4 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vwsll.vi` | `logical-shift` | `exact` |

### `integer-widen-accumulate`（2）

| opcode | 合法 operand form | SEW | LMUL | mask（宽/保守） | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vwmacc.vv` | `wide vd, narrow vs1, narrow vs2` | e8/e16/e32 | mf8/mf4/mf2/m1/m2/m4 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vwmacc.vv` | `signed` | `exact` |
| `vwmacc.vx` | `wide vd, rs1, narrow vs2[, v0.t]`<br>`wide vd, rs1, narrow vs2[, v0.t], v0.t` | e8/e16/e32 | mf8/mf4/mf2/m1/m2/m4 | `v0-only / v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `vwmacc.vx` | `signed` | `exact` |

### `integer-widen-multiply`（5）

| opcode | 合法 operand form | SEW | LMUL | mask（宽/保守） | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vwmul.vv` | `wide vd, narrow operands` | e8/e16/e32 | mf8/mf4/mf2/m1/m2/m4 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vwmul.vv` | `signed-widen-multiply` | `exact` |
| `vwmul.vx` | `wide vd, narrow operands` | e8/e16/e32 | mf8/mf4/mf2/m1/m2/m4 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vwmul.vx` | `signed-widen-multiply` | `exact` |
| `vwmulsu.vv` | `wide vd, narrow operands` | e8/e16/e32 | mf8/mf4/mf2/m1/m2/m4 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vwmulsu.vv` | `signed-times-unsigned-widen-multiply` | `exact` |
| `vwmulu.vv` | `wide vd, narrow operands` | e8/e16/e32 | mf8/mf4/mf2/m1/m2/m4 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vwmulu.vv` | `unsigned-widen-multiply` | `exact` |
| `vwmulu.vx` | `wide vd, narrow operands` | e8/e16/e32 | mf8/mf4/mf2/m1/m2/m4 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vwmulu.vx` | `unsigned-widen-multiply` | `exact` |

### `integer-widen-reduction`（1）

| opcode | 合法 operand form | SEW | LMUL | mask（宽/保守） | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vwredsum.vs` | `wide vd, narrow vs2, wide vs1[, v0.t]`<br>`wide vd, narrow vs2, wide vs1[, v0.t], v0.t` | e8/e16/e32 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only / v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `vwredsum.vs` | `signed` | `exact` |

### `mask-compare`（14）

| opcode | 合法 operand form | SEW | LMUL | mask（宽/保守） | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vmfgt.vf` | `vd-mask, vs2, rs1` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmfgt.vf` | `floating` | `quiet-compare` |
| `vmfle.vf` | `vd-mask, vs2, rs1` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmfle.vf` | `floating` | `quiet-compare` |
| `vmfne.vf` | `vd-mask, vs2, rs1` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmfne.vf` | `floating` | `quiet-compare` |
| `vmseq.vi` | `vd-mask, vs2, simm5` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmseq.vi` | `equality-compare` | `exact` |
| `vmseq.vx` | `vd-mask, vs2, rs1` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmseq.vx` | `equality-compare` | `exact` |
| `vmsgtu.vi` | `vd-mask, vs2, simm5` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmsgtu.vi` | `unsigned-compare` | `exact` |
| `vmsgtu.vx` | `vd-mask, vs2, rs1` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmsgtu.vx` | `unsigned-compare` | `exact` |
| `vmsle.vi` | `vd-mask, vs2, simm5` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmsle.vi` | `signed-compare` | `exact` |
| `vmsleu.vi` | `vd-mask, vs2, simm5` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmsleu.vi` | `unsigned-compare` | `exact` |
| `vmsleu.vv` | `vd-mask, vs2, vs1` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmsleu.vv` | `unsigned-compare` | `exact` |
| `vmsltu.vv` | `vd-mask, vs2, vs1` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmsltu.vv` | `unsigned-compare` | `exact` |
| `vmsltu.vx` | `vd-mask, vs2, rs1` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmsltu.vx` | `unsigned-compare` | `exact` |
| `vmsne.vi` | `vd-mask, vs2, simm5` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmsne.vi` | `equality-compare` | `exact` |
| `vmsne.vv` | `vd-mask, vs2, vs1` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmsne.vv` | `equality-compare` | `exact` |

### `mask-load`（1）

| opcode | 合法 operand form | SEW | LMUL | mask（宽/保守） | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vlm.v` | `vd-mask, (rs1)` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vlm.v` | `mask-bits` | `exact` |

### `mask-logic`（4）

| opcode | 合法 operand form | SEW | LMUL | mask（宽/保守） | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vmand.mm` | `vd-mask, vs2-mask, vs1-mask` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmand.mm` | `mask-bits` | `exact` |
| `vmclr.m` | `vd-mask` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmclr.m` | `mask-bits` | `exact` |
| `vmnot.m` | `vd-mask, vs2-mask` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmnot.m` | `mask-bits` | `exact` |
| `vmor.mm` | `vd-mask, vs2-mask, vs1-mask` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmor.mm` | `mask-bits` | `exact` |

### `mask-merge`（3）

| opcode | 合法 operand form | SEW | LMUL | mask（宽/保守） | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vmerge.vim` | `vd, vs2, source, v0` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmerge.vim` | `bit-preserving` | `exact` |
| `vmerge.vvm` | `vd, vs2, source, v0` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmerge.vvm` | `bit-preserving` | `exact` |
| `vmerge.vxm` | `vd, vs2, source, v0` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmerge.vxm` | `bit-preserving` | `exact` |

### `mask-scan`（2）

| opcode | 合法 operand form | SEW | LMUL | mask（宽/保守） | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vcpop.m` | `rd, vs2-mask` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `not-applicable` | `require-zero` | 否 | 否 | `vcpop.m` | `mask-bits` | `exact` |
| `vfirst.m` | `rd, vs2-mask` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `not-applicable` | `require-zero` | 否 | 否 | `vfirst.m` | `mask-bits` | `exact` |

### `memory`（44）

| opcode | 合法 operand form | SEW | LMUL | mask（宽/保守） | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vl1r.v` | `raw-vector-group, (rs1)` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden / forbidden` | `not-applicable` | `require-zero` | 否 | 是 | `vl1r.v` | `raw-bytes` | `not-applicable` |
| `vl1re16.v` | `raw-vector-group, (rs1)` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden / forbidden` | `not-applicable` | `require-zero` | 否 | 是 | `vl1re16.v` | `raw-bytes` | `not-applicable` |
| `vl1re32.v` | `raw-vector-group, (rs1)` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden / forbidden` | `not-applicable` | `require-zero` | 否 | 是 | `vl1re32.v` | `raw-bytes` | `not-applicable` |
| `vl1re64.v` | `raw-vector-group, (rs1)` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden / forbidden` | `not-applicable` | `require-zero` | 否 | 是 | `vl1re64.v` | `raw-bytes` | `not-applicable` |
| `vl2r.v` | `raw-vector-group, (rs1)` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden / forbidden` | `not-applicable` | `require-zero` | 否 | 是 | `vl2r.v` | `raw-bytes` | `not-applicable` |
| `vl2re16.v` | `raw-vector-group, (rs1)` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden / forbidden` | `not-applicable` | `require-zero` | 否 | 是 | `vl2re16.v` | `raw-bytes` | `not-applicable` |
| `vl2re32.v` | `raw-vector-group, (rs1)` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden / forbidden` | `not-applicable` | `require-zero` | 否 | 是 | `vl2re32.v` | `raw-bytes` | `not-applicable` |
| `vl4r.v` | `raw-vector-group, (rs1)` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden / forbidden` | `not-applicable` | `require-zero` | 否 | 是 | `vl4r.v` | `raw-bytes` | `not-applicable` |
| `vl4re16.v` | `raw-vector-group, (rs1)` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden / forbidden` | `not-applicable` | `require-zero` | 否 | 是 | `vl4re16.v` | `raw-bytes` | `not-applicable` |
| `vl4re32.v` | `raw-vector-group, (rs1)` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden / forbidden` | `not-applicable` | `require-zero` | 否 | 是 | `vl4re32.v` | `raw-bytes` | `not-applicable` |
| `vl4re64.v` | `raw-vector-group, (rs1)` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden / forbidden` | `not-applicable` | `require-zero` | 否 | 是 | `vl4re64.v` | `raw-bytes` | `not-applicable` |
| `vl8re32.v` | `raw-vector-group, (rs1)` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden / forbidden` | `not-applicable` | `require-zero` | 否 | 是 | `vl8re32.v` | `raw-bytes` | `not-applicable` |
| `vl8re64.v` | `raw-vector-group, (rs1)` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden / forbidden` | `not-applicable` | `require-zero` | 否 | 是 | `vl8re64.v` | `raw-bytes` | `not-applicable` |
| `vle16.v` | `vd, (rs1)[, v0.t]`<br>`vd, (rs1)[, v0.t], v0.t` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only / v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `vle16.v` | `raw-elements` | `exact` |
| `vle32.v` | `vd, (rs1)[, v0.t]`<br>`vd, (rs1)[, v0.t], v0.t` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only / v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `vle32.v` | `raw-elements` | `exact` |
| `vle64.v` | `vd, (rs1)[, v0.t]`<br>`vd, (rs1)[, v0.t], v0.t` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only / v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `vle64.v` | `raw-elements` | `exact` |
| `vle8.v` | `vd, (rs1)[, v0.t]`<br>`vd, (rs1)[, v0.t], v0.t` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only / v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `vle8.v` | `raw-elements` | `exact` |
| `vle8ff.v` | `vd, (rs1)` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vle8ff.v` | `raw-elements` | `exact` |
| `vlse16.v` | `vd, (rs1), rs2-stride[, v0.t]`<br>`vd, (rs1), rs2-stride[, v0.t], v0.t` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only / v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `vlse16.v` | `raw-elements` | `exact` |
| `vlse32.v` | `vd, (rs1), rs2-stride[, v0.t]`<br>`vd, (rs1), rs2-stride[, v0.t], v0.t` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only / v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `vlse32.v` | `raw-elements` | `exact` |
| `vlse64.v` | `vd, (rs1), rs2-stride[, v0.t]`<br>`vd, (rs1), rs2-stride[, v0.t], v0.t` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only / v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `vlse64.v` | `raw-elements` | `exact` |
| `vlse8.v` | `vd, (rs1), rs2-stride[, v0.t]`<br>`vd, (rs1), rs2-stride[, v0.t], v0.t` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only / v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `vlse8.v` | `raw-elements` | `exact` |
| `vlseg2e32.v` | `vd-group, (rs1)` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vlseg2e32.v` | `raw-elements` | `exact` |
| `vlseg2e64.v` | `vd-group, (rs1)` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vlseg2e64.v` | `raw-elements` | `exact` |
| `vlsseg2e32.v` | `vd-group, (rs1), rs2-stride` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vlsseg2e32.v` | `raw-elements` | `exact` |
| `vlsseg2e64.v` | `vd-group, (rs1), rs2-stride` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vlsseg2e64.v` | `raw-elements` | `exact` |
| `vluxei16.v` | `vd, (rs1), index-vector` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vluxei16.v` | `unsigned-index` | `exact` |
| `vluxei64.v` | `vd, (rs1), index-vector` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vluxei64.v` | `unsigned-index` | `exact` |
| `vs1r.v` | `raw-vector-group, (rs1)` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden / forbidden` | `not-applicable` | `require-zero` | 否 | 是 | `vs1r.v` | `raw-bytes` | `not-applicable` |
| `vs2r.v` | `raw-vector-group, (rs1)` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden / forbidden` | `not-applicable` | `require-zero` | 否 | 是 | `vs2r.v` | `raw-bytes` | `not-applicable` |
| `vs4r.v` | `raw-vector-group, (rs1)` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden / forbidden` | `not-applicable` | `require-zero` | 否 | 是 | `vs4r.v` | `raw-bytes` | `not-applicable` |
| `vs8r.v` | `raw-vector-group, (rs1)` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden / forbidden` | `not-applicable` | `require-zero` | 否 | 是 | `vs8r.v` | `raw-bytes` | `not-applicable` |
| `vse16.v` | `vs3, (rs1)[, v0.t]`<br>`vs3, (rs1)[, v0.t], v0.t` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only / v0-only` | `not-applicable` | `require-zero` | 是 | 否 | `vse16.v` | `raw-elements` | `exact` |
| `vse32.v` | `vs3, (rs1)[, v0.t]`<br>`vs3, (rs1)[, v0.t], v0.t` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only / v0-only` | `not-applicable` | `require-zero` | 是 | 否 | `vse32.v` | `raw-elements` | `exact` |
| `vse64.v` | `vs3, (rs1)[, v0.t]`<br>`vs3, (rs1)[, v0.t], v0.t` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only / v0-only` | `not-applicable` | `require-zero` | 是 | 否 | `vse64.v` | `raw-elements` | `exact` |
| `vse8.v` | `vs3, (rs1)[, v0.t]`<br>`vs3, (rs1)[, v0.t], v0.t` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only / v0-only` | `not-applicable` | `require-zero` | 是 | 否 | `vse8.v` | `raw-elements` | `exact` |
| `vsm.v` | `vs3-mask, (rs1)` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `not-applicable` | `require-zero` | 否 | 否 | `vsm.v` | `mask-bits` | `exact` |
| `vsse32.v` | `vs3, (rs1), rs2-stride[, v0.t]`<br>`vs3, (rs1), rs2-stride[, v0.t], v0.t` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only / v0-only` | `not-applicable` | `require-zero` | 是 | 否 | `vsse32.v` | `raw-elements` | `exact` |
| `vsse64.v` | `vs3, (rs1), rs2-stride[, v0.t]`<br>`vs3, (rs1), rs2-stride[, v0.t], v0.t` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only / v0-only` | `not-applicable` | `require-zero` | 是 | 否 | `vsse64.v` | `raw-elements` | `exact` |
| `vsseg2e32.v` | `vs3-group, (rs1)` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `not-applicable` | `require-zero` | 否 | 否 | `vsseg2e32.v` | `raw-elements` | `exact` |
| `vsseg2e64.v` | `vs3-group, (rs1)` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `not-applicable` | `require-zero` | 否 | 否 | `vsseg2e64.v` | `raw-elements` | `exact` |
| `vsseg4e64.v` | `vs3-group, (rs1)` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `not-applicable` | `require-zero` | 否 | 否 | `vsseg4e64.v` | `raw-elements` | `exact` |
| `vssseg2e32.v` | `vs3-group, (rs1), rs2-stride` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `not-applicable` | `require-zero` | 否 | 否 | `vssseg2e32.v` | `raw-elements` | `exact` |
| `vssseg2e64.v` | `vs3-group, (rs1), rs2-stride` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `not-applicable` | `require-zero` | 否 | 否 | `vssseg2e64.v` | `raw-elements` | `exact` |

### `slide`（5）

| opcode | 合法 operand form | SEW | LMUL | mask（宽/保守） | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vslide1down.vx` | `vd, vs2, rs1` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vslide1down.vx` | `bit-preserving` | `exact` |
| `vslide1up.vx` | `vd, vs2, rs1` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vslide1up.vx` | `bit-preserving` | `exact` |
| `vslidedown.vi` | `vd, vs2, offset` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vslidedown.vi` | `unsigned-offset` | `exact` |
| `vslidedown.vx` | `vd, vs2, offset` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vslidedown.vx` | `unsigned-offset` | `exact` |
| `vslideup.vi` | `vd, vs2, offset` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden / forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vslideup.vi` | `unsigned-offset` | `exact` |

### `whole-register`（3）

| opcode | 合法 operand form | SEW | LMUL | mask（宽/保守） | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vl2re64.v` | `raw-vector-group, (rs1)` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden / forbidden` | `not-applicable` | `require-zero` | 否 | 是 | `vl2re64.v` | `raw-bytes` | `not-applicable` |
| `vl8r.v` | `raw-vector-group, (rs1)` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden / forbidden` | `not-applicable` | `require-zero` | 否 | 是 | `vl8r.v` | `raw-bytes` | `not-applicable` |
| `vl8re16.v` | `raw-vector-group, (rs1)` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden / forbidden` | `not-applicable` | `require-zero` | 否 | 是 | `vl8re16.v` | `raw-bytes` | `not-applicable` |

## RVV256→RVV1024 过渡后端

该实验路径仍在写出正式汇编前完成 CFG/vtype 预检；可由单条 ebreak 安全表示的未知入口或未验证 form 会保留诊断并生成 fallback。

注册总数：**205**。分类计数：config=3, convert-narrow=4, csr-read=1, csr-write=12, float-convert=4, float-convert-widen=5, float-fused=7, float-move=3, float-reduction=3, float-reduction-widen=2, float-same-width=10, float-unary=2, float-widen=2, gather=2, integer-accumulate=4, integer-convert-widen=2, integer-extend=6, integer-index=1, integer-move=5, integer-narrow=3, integer-reduction=3, integer-reduction-widen=1, integer-same-width=26, integer-shift-widen=1, integer-unary=1, integer-wide-narrow=2, integer-widen=7, integer-widen-accumulate=2, mask-compare=15, mask-load=1, mask-logic=4, mask-merge=3, mask-scan=2, memory-fof-load=1, memory-load=4, memory-load-indexed=2, memory-load-strided=4, memory-mask-store=1, memory-segment-load=4, memory-segment-store=5, memory-store=4, memory-store-strided=4, slide=5, whole-register-load=14, whole-register-move=4, whole-register-store=4。

### `config`（3）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vsetivli` | `rd, uimm5, eSEW, LMUL, tail, mask` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `not-applicable` | 否 | 否 | `vsetivli` | `not-applicable` | `not-applicable` |
| `vsetvl` | `rd, rs1, rs2` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `not-applicable` | 否 | 否 | `vsetvl` | `not-applicable` | `not-applicable` |
| `vsetvli` | `rd, rs1, eSEW, LMUL, tail, mask` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `not-applicable` | 否 | 否 | `vsetvli` | `not-applicable` | `not-applicable` |

### `convert-narrow`（4）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vfncvt.f.f.w` | `narrow vd, wide vs2[, v0.t]` | e8/e16/e32 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 否 | 否 | `vfncvt.f.f.w` | `floating-point` | `architectural-frm` |
| `vfncvt.f.xu.w` | `narrow vd, wide vs2` | e8/e16/e32 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vfncvt.f.xu.w` | `unsigned-integer-to-floating-point` | `architectural-frm` |
| `vfncvt.x.f.w` | `narrow vd, wide vs2` | e8/e16/e32 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vfncvt.x.f.w` | `floating-point-to-signed-integer` | `architectural-frm` |
| `vncvt.x.x.w` | `narrow vd, wide vs2` | e8/e16/e32 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vncvt.x.x.w` | `signed-integer` | `exact-integer` |

### `csr-read`（1）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `csrr` | `rd, vector-csr` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `not-applicable` | 否 | 是 | `csrr` | `not-applicable` | `not-applicable` |

### `csr-write`（12）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `csrc` | `vector-csr write/read-modify-write form` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `not-applicable` | 否 | 是 | `csrc` | `bitfield` | `exact-integer` |
| `csrci` | `vector-csr write/read-modify-write form` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `not-applicable` | 否 | 是 | `csrci` | `bitfield` | `exact-integer` |
| `csrrc` | `vector-csr write/read-modify-write form` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `not-applicable` | 否 | 是 | `csrrc` | `bitfield` | `exact-integer` |
| `csrrci` | `vector-csr write/read-modify-write form` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `not-applicable` | 否 | 是 | `csrrci` | `bitfield` | `exact-integer` |
| `csrrs` | `vector-csr write/read-modify-write form` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `not-applicable` | 否 | 是 | `csrrs` | `bitfield` | `exact-integer` |
| `csrrsi` | `vector-csr write/read-modify-write form` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `not-applicable` | 否 | 是 | `csrrsi` | `bitfield` | `exact-integer` |
| `csrrw` | `vector-csr write/read-modify-write form` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `not-applicable` | 否 | 是 | `csrrw` | `bitfield` | `exact-integer` |
| `csrrwi` | `vector-csr write/read-modify-write form` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `not-applicable` | 否 | 是 | `csrrwi` | `bitfield` | `exact-integer` |
| `csrs` | `vector-csr write/read-modify-write form` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `not-applicable` | 否 | 是 | `csrs` | `bitfield` | `exact-integer` |
| `csrsi` | `vector-csr write/read-modify-write form` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `not-applicable` | 否 | 是 | `csrsi` | `bitfield` | `exact-integer` |
| `csrw` | `vector-csr write/read-modify-write form` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `not-applicable` | 否 | 是 | `csrw` | `bitfield` | `exact-integer` |
| `csrwi` | `vector-csr write/read-modify-write form` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `not-applicable` | 否 | 是 | `csrwi` | `bitfield` | `exact-integer` |

### `float-convert`（4）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vfcvt.f.x.v` | `vd, vs2[, v0.t]` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 否 | 否 | `vfcvt.f.x.v` | `floating-point` | `architectural-frm` |
| `vfcvt.f.xu.v` | `vd, vs2` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vfcvt.f.xu.v` | `floating-point` | `architectural-frm` |
| `vfcvt.x.f.v` | `vd, vs2[, v0.t]` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 否 | 否 | `vfcvt.x.f.v` | `floating-point` | `architectural-frm` |
| `vfcvt.xu.f.v` | `vd, vs2` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vfcvt.xu.f.v` | `floating-point` | `architectural-frm` |

### `float-convert-widen`（5）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vfwcvt.f.f.v` | `wide vd, narrow vs2` | e16/e32 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vfwcvt.f.f.v` | `floating-point` | `architectural-frm` |
| `vfwcvt.f.x.v` | `wide vd, narrow vs2` | e16/e32 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vfwcvt.f.x.v` | `signed-integer-to-floating-point` | `architectural-frm` |
| `vfwcvt.f.xu.v` | `wide vd, narrow vs2` | e16/e32 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vfwcvt.f.xu.v` | `unsigned-integer-to-floating-point` | `architectural-frm` |
| `vfwcvt.x.f.v` | `wide vd, narrow vs2` | e16/e32 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vfwcvt.x.f.v` | `floating-point-to-signed-integer` | `architectural-frm` |
| `vfwcvt.xu.f.v` | `wide vd, narrow vs2` | e16/e32 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vfwcvt.xu.f.v` | `floating-point-to-unsigned-integer` | `architectural-frm` |

### `float-fused`（7）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vfmacc.vf` | `vd, fs1, vs2` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vfmacc.vf` | `floating-point` | `architectural-frm` |
| `vfmacc.vv` | `vd, vs1, vs2` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vfmacc.vv` | `floating-point` | `architectural-frm` |
| `vfmadd.vf` | `vd, fs1, vs2` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vfmadd.vf` | `floating-point` | `architectural-frm` |
| `vfmadd.vv` | `vd, vs1, vs2` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vfmadd.vv` | `floating-point` | `architectural-frm` |
| `vfmsac.vv` | `vd, vs1, vs2` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vfmsac.vv` | `floating-point` | `architectural-frm` |
| `vfmsub.vv` | `vd, vs1, vs2` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vfmsub.vv` | `floating-point` | `architectural-frm` |
| `vfnmsac.vf` | `vd, fs1, vs2` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vfnmsac.vf` | `floating-point` | `architectural-frm` |

### `float-move`（3）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vfmv.f.s` | `fp-rd, vs2` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `not-applicable` | `require-zero` | 否 | 否 | `vfmv.f.s` | `floating-point` | `not-applicable` |
| `vfmv.s.f` | `destination, source` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vfmv.s.f` | `floating-point` | `not-applicable` |
| `vfmv.v.f` | `destination, source` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vfmv.v.f` | `floating-point` | `not-applicable` |

### `float-reduction`（3）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vfredmax.vs` | `vd(m1), vs2(LMUL), vs1(m1)` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vfredmax.vs` | `floating-point` | `architectural-frm` |
| `vfredmin.vs` | `vd(m1), vs2(LMUL), vs1(m1)` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vfredmin.vs` | `floating-point` | `architectural-frm` |
| `vfredusum.vs` | `vd(m1), vs2(LMUL), vs1(m1)` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vfredusum.vs` | `floating-point` | `architectural-frm` |

### `float-reduction-widen`（2）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vfwredosum.vs` | `wide vd(m1), narrow vs2(LMUL), wide vs1(m1)` | e16/e32 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vfwredosum.vs` | `floating-point` | `architectural-frm` |
| `vfwredusum.vs` | `wide vd(m1), narrow vs2(LMUL), wide vs1(m1)` | e16/e32 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vfwredusum.vs` | `floating-point` | `architectural-frm` |

### `float-same-width`（10）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vfadd.vf` | `vd, vs2, fs1[, v0.t]` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 否 | 否 | `vfadd.vf` | `floating-point` | `architectural-frm` |
| `vfadd.vv` | `vd, vs2, vs1[, v0.t]` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 否 | 否 | `vfadd.vv` | `floating-point` | `architectural-frm` |
| `vfdiv.vv` | `vd, vs2, vs1` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vfdiv.vv` | `floating-point` | `architectural-frm` |
| `vfmax.vv` | `vd, vs2, vs1` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vfmax.vv` | `floating-point` | `architectural-frm` |
| `vfmin.vv` | `vd, vs2, vs1` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vfmin.vv` | `floating-point` | `architectural-frm` |
| `vfmul.vf` | `vd, vs2, fs1[, v0.t]` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 否 | 否 | `vfmul.vf` | `floating-point` | `architectural-frm` |
| `vfmul.vv` | `vd, vs2, vs1[, v0.t]` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 否 | 否 | `vfmul.vv` | `floating-point` | `architectural-frm` |
| `vfrsub.vf` | `vd, vs2, fs1` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vfrsub.vf` | `floating-point` | `architectural-frm` |
| `vfsub.vf` | `vd, vs2, fs1` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vfsub.vf` | `floating-point` | `architectural-frm` |
| `vfsub.vv` | `vd, vs2, vs1` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vfsub.vv` | `floating-point` | `architectural-frm` |

### `float-unary`（2）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vfabs.v` | `vd, vs2` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vfabs.v` | `floating-point` | `architectural-frm` |
| `vfneg.v` | `vd, vs2[, v0.t]` | e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 否 | 否 | `vfneg.v` | `floating-point` | `architectural-frm` |

### `float-widen`（2）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vfwmacc.vv` | `wide vd, narrow vector/scalar sources` | e16/e32 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vfwmacc.vv` | `floating-point` | `architectural-frm` |
| `vfwmul.vf` | `wide vd, narrow vector/scalar sources` | e16/e32 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vfwmul.vf` | `floating-point` | `architectural-frm` |

### `gather`（2）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vrgather.vv` | `vd, data vs2, index vs1` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vrgather.vv` | `unsigned-index` | `exact-integer` |
| `vrgatherei16.vv` | `vd, data vs2, e16-index vs1` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vrgatherei16.vv` | `unsigned-index` | `exact-integer` |

### `integer-accumulate`（4）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vmacc.vv` | `vd, vs1, vs2` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vmacc.vv` | `modular-integer` | `exact-integer` |
| `vmacc.vx` | `vd, rs1, vs2` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vmacc.vx` | `modular-integer` | `exact-integer` |
| `vmadd.vv` | `vd, vs1, vs2` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vmadd.vv` | `modular-integer` | `exact-integer` |
| `vmadd.vx` | `vd, rs1, vs2` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vmadd.vx` | `modular-integer` | `exact-integer` |

### `integer-convert-widen`（2）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vwcvt.x.x.v` | `wide vd, narrow vs2` | e8/e16/e32 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vwcvt.x.x.v` | `signed-integer` | `exact-integer` |
| `vwcvtu.x.x.v` | `wide vd, narrow vs2` | e8/e16/e32 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vwcvtu.x.x.v` | `unsigned-integer` | `exact-integer` |

### `integer-extend`（6）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vsext.vf2` | `vd, narrow vs2 (factor 2)` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vsext.vf2` | `signed-extension` | `exact-integer` |
| `vsext.vf4` | `vd, narrow vs2 (factor 4)` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vsext.vf4` | `signed-extension` | `exact-integer` |
| `vsext.vf8` | `vd, narrow vs2 (factor 8)` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vsext.vf8` | `signed-extension` | `exact-integer` |
| `vzext.vf2` | `vd, narrow vs2 (factor 2)` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vzext.vf2` | `zero-extension` | `exact-integer` |
| `vzext.vf4` | `vd, narrow vs2 (factor 4)` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vzext.vf4` | `zero-extension` | `exact-integer` |
| `vzext.vf8` | `vd, narrow vs2 (factor 8)` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vzext.vf8` | `zero-extension` | `exact-integer` |

### `integer-index`（1）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vid.v` | `vd` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vid.v` | `unsigned-index` | `exact-integer` |

### `integer-move`（5）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vmv.s.x` | `destination, source` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmv.s.x` | `bit-preserving` | `exact-integer` |
| `vmv.v.i` | `vd, simm5` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmv.v.i` | `bit-preserving` | `exact-integer` |
| `vmv.v.v` | `destination, source` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmv.v.v` | `bit-preserving` | `exact-integer` |
| `vmv.v.x` | `destination, source` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmv.v.x` | `bit-preserving` | `exact-integer` |
| `vmv.x.s` | `rd, vs2` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `not-applicable` | `require-zero` | 否 | 否 | `vmv.x.s` | `bit-preserving` | `exact-integer` |

### `integer-narrow`（3）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vnclip.wi` | `narrow vd, wide vs2, uimm5` | e8/e16/e32 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vnclip.wi` | `signed-fixed-point` | `architectural-vxrm` |
| `vnsra.wi` | `narrow vd, wide vs2, uimm5` | e8/e16/e32 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vnsra.wi` | `arithmetic-shift` | `exact-integer` |
| `vnsrl.wi` | `narrow vd, wide vs2, uimm5` | e8/e16/e32 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vnsrl.wi` | `logical-shift` | `exact-integer` |

### `integer-reduction`（3）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vredmaxu.vs` | `vd(m1), vs2(LMUL), vs1(m1)` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vredmaxu.vs` | `unsigned-integer` | `exact-integer` |
| `vredor.vs` | `vd(m1), vs2(LMUL), vs1(m1)` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vredor.vs` | `bitwise` | `exact-integer` |
| `vredsum.vs` | `vd(m1), vs2(LMUL), vs1(m1)` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vredsum.vs` | `modular-reduction` | `exact-integer` |

### `integer-reduction-widen`（1）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vwredsum.vs` | `wide vd(m1), narrow vs2(LMUL), wide vs1(m1)[, v0.t]` | e8/e16/e32 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `vwredsum.vs` | `signed-integer` | `exact-integer` |

### `integer-same-width`（26）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vadd.vi` | `vd, vs2, simm5[, v0.t]` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 否 | 否 | `vadd.vi` | `modular-integer` | `exact-integer` |
| `vadd.vv` | `vd, vs2, vs1[, v0.t]` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 否 | 否 | `vadd.vv` | `modular-integer` | `exact-integer` |
| `vadd.vx` | `vd, vs2, rs1[, v0.t]` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 否 | 否 | `vadd.vx` | `modular-integer` | `exact-integer` |
| `vand.vi` | `vd, vs2, simm5[, v0.t]` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 否 | 否 | `vand.vi` | `bitwise` | `exact-integer` |
| `vand.vv` | `vd, vs2, vs1[, v0.t]` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 否 | 否 | `vand.vv` | `bitwise` | `exact-integer` |
| `vand.vx` | `vd, vs2, rs1[, v0.t]` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 否 | 否 | `vand.vx` | `bitwise` | `exact-integer` |
| `vandn.vv` | `vd, vs2, vs1` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vxor.vi+vand.vv` | `bitwise` | `exact-integer` |
| `vdiv.vx` | `vd, vs2, rs1` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vdiv.vx` | `signed-integer` | `exact-integer` |
| `vmax.vv` | `vd, vs2, vs1` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmax.vv` | `signed-integer` | `exact-integer` |
| `vmaxu.vv` | `vd, vs2, vs1` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmaxu.vv` | `unsigned-integer` | `exact-integer` |
| `vmul.vv` | `vd, vs2, vs1[, v0.t]` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 否 | 否 | `vmul.vv` | `modular-integer` | `exact-integer` |
| `vmul.vx` | `vd, vs2, rs1[, v0.t]` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 否 | 否 | `vmul.vx` | `modular-integer` | `exact-integer` |
| `vor.vi` | `vd, vs2, simm5[, v0.t]` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 否 | 否 | `vor.vi` | `bitwise` | `exact-integer` |
| `vor.vv` | `vd, vs2, vs1[, v0.t]` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 否 | 否 | `vor.vv` | `bitwise` | `exact-integer` |
| `vor.vx` | `vd, vs2, rs1[, v0.t]` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 否 | 否 | `vor.vx` | `bitwise` | `exact-integer` |
| `vrsub.vi` | `vd, vs2, simm5[, v0.t]` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 否 | 否 | `vrsub.vi` | `modular-integer` | `exact-integer` |
| `vsll.vi` | `vd, vs2, uimm5[, v0.t]` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 否 | 否 | `vsll.vi` | `logical-shift` | `exact-integer` |
| `vsll.vv` | `vd, vs2, vs1[, v0.t]` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 否 | 否 | `vsll.vv` | `logical-shift` | `exact-integer` |
| `vsll.vx` | `vd, vs2, rs1[, v0.t]` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 否 | 否 | `vsll.vx` | `logical-shift` | `exact-integer` |
| `vsra.vi` | `vd, vs2, uimm5[, v0.t]` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 否 | 否 | `vsra.vi` | `arithmetic-shift` | `exact-integer` |
| `vsrl.vi` | `vd, vs2, uimm5[, v0.t]` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 否 | 否 | `vsrl.vi` | `logical-shift` | `exact-integer` |
| `vsrl.vv` | `vd, vs2, vs1[, v0.t]` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 否 | 否 | `vsrl.vv` | `logical-shift` | `exact-integer` |
| `vsrl.vx` | `vd, vs2, rs1[, v0.t]` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 否 | 否 | `vsrl.vx` | `logical-shift` | `exact-integer` |
| `vsub.vv` | `vd, vs2, vs1[, v0.t]` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 否 | 否 | `vsub.vv` | `modular-integer` | `exact-integer` |
| `vsub.vx` | `vd, vs2, rs1[, v0.t]` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 否 | 否 | `vsub.vx` | `modular-integer` | `exact-integer` |
| `vxor.vv` | `vd, vs2, vs1[, v0.t]` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 否 | 否 | `vxor.vv` | `bitwise` | `exact-integer` |

### `integer-shift-widen`（1）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vwsll.vi` | `wide vd, narrow vs2, uimm5` | e8/e16/e32 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vwsll.vi` | `logical-shift` | `exact-integer` |

### `integer-unary`（1）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vnot.v` | `vd, vs2` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vxor.vi` | `bitwise` | `exact-integer` |

### `integer-wide-narrow`（2）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vwadd.wv` | `wide vd, wide vs2, narrow vs1` | e8/e16/e32 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vwadd.wv` | `signed-widen-add` | `exact-integer` |
| `vwaddu.wv` | `wide vd, wide vs2, narrow vs1` | e8/e16/e32 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vwaddu.wv` | `unsigned-widen-add` | `exact-integer` |

### `integer-widen`（7）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vwadd.vv` | `wide vd, narrow vs2, narrow vs1` | e8/e16/e32 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vwadd.vv` | `signed-widen-add` | `exact-integer` |
| `vwaddu.vx` | `wide vd, narrow vs2, scalar source` | e8/e16/e32 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vwaddu.vx` | `unsigned-widen-add` | `exact-integer` |
| `vwmul.vv` | `wide vd, narrow vector/scalar sources` | e8/e16/e32 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vwmul.vv` | `signed-widen-multiply` | `exact-integer` |
| `vwmul.vx` | `wide vd, narrow vector/scalar sources` | e8/e16/e32 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vwmul.vx` | `signed-widen-multiply` | `exact-integer` |
| `vwmulsu.vv` | `wide vd, narrow vector/scalar sources` | e8/e16/e32 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vwmulsu.vv` | `signed-times-unsigned-widen-multiply` | `exact-integer` |
| `vwmulu.vv` | `wide vd, narrow vector/scalar sources` | e8/e16/e32 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vwmulu.vv` | `unsigned-widen-multiply` | `exact-integer` |
| `vwmulu.vx` | `wide vd, narrow vector/scalar sources` | e8/e16/e32 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vwmulu.vx` | `unsigned-widen-multiply` | `exact-integer` |

### `integer-widen-accumulate`（2）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vwmacc.vv` | `wide vd, narrow vector/scalar sources[, v0.t]` | e8/e16/e32 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `vwmacc.vv` | `signed-widen-multiply` | `exact-integer` |
| `vwmacc.vx` | `wide vd, narrow vector/scalar sources[, v0.t]` | e8/e16/e32 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `vwmacc.vx` | `signed-widen-multiply` | `exact-integer` |

### `mask-compare`（15）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vmfgt.vf` | `mask vd, data vs2, vector/scalar/immediate source` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmfgt.vf` | `floating-point-compare` | `exact-integer` |
| `vmfle.vf` | `mask vd, data vs2, vector/scalar/immediate source` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmfle.vf` | `floating-point-compare` | `exact-integer` |
| `vmfne.vf` | `mask vd, data vs2, vector/scalar/immediate source` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmfne.vf` | `floating-point-compare` | `exact-integer` |
| `vmseq.vi` | `mask vd, data vs2, vector/scalar/immediate source` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmseq.vi` | `equality-compare` | `exact-integer` |
| `vmseq.vx` | `mask vd, data vs2, vector/scalar/immediate source` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmseq.vx` | `equality-compare` | `exact-integer` |
| `vmsgtu.vi` | `mask vd, data vs2, vector/scalar/immediate source` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmsgtu.vi` | `unsigned-compare` | `exact-integer` |
| `vmsgtu.vx` | `mask vd, data vs2, vector/scalar/immediate source` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmsgtu.vx` | `unsigned-compare` | `exact-integer` |
| `vmsle.vi` | `mask vd, data vs2, vector/scalar/immediate source` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmsle.vi` | `signed-compare` | `exact-integer` |
| `vmsleu.vi` | `mask vd, data vs2, vector/scalar/immediate source` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmsleu.vi` | `unsigned-compare` | `exact-integer` |
| `vmsleu.vv` | `mask vd, data vs2, vector/scalar/immediate source` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmsleu.vv` | `unsigned-compare` | `exact-integer` |
| `vmsltu.vv` | `mask vd, data vs2, vector/scalar/immediate source` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmsltu.vv` | `unsigned-compare` | `exact-integer` |
| `vmsltu.vx` | `mask vd, data vs2, vector/scalar/immediate source` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmsltu.vx` | `unsigned-compare` | `exact-integer` |
| `vmsne.vi` | `mask vd, data vs2, vector/scalar/immediate source` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmsne.vi` | `equality-compare` | `exact-integer` |
| `vmsne.vv` | `mask vd, data vs2, vector/scalar/immediate source` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmsne.vv` | `equality-compare` | `exact-integer` |
| `vmsne.vx` | `mask vd, data vs2, vector/scalar/immediate source` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmsne.vx` | `equality-compare` | `exact-integer` |

### `mask-load`（1）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vlm.v` | `vd(mask), (rs1)` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vlm.v` | `mask-bit` | `exact-integer` |

### `mask-logic`（4）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vmand.mm` | `mask vd, mask vs2, mask vs1` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmand.mm` | `mask-bit` | `exact-integer` |
| `vmclr.m` | `mask vd` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmclr.m` | `mask-bit` | `exact-integer` |
| `vmnot.m` | `mask vd, mask vs2` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmnot.m` | `mask-bit` | `exact-integer` |
| `vmor.mm` | `mask vd, mask vs2, mask vs1` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vmor.mm` | `mask-bit` | `exact-integer` |

### `mask-merge`（3）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vmerge.vim` | `vd, vs2, vector/scalar/immediate source, v0` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vmerge.vim` | `bit-preserving` | `exact-integer` |
| `vmerge.vvm` | `vd, vs2, vector/scalar/immediate source, v0` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vmerge.vvm` | `bit-preserving` | `exact-integer` |
| `vmerge.vxm` | `vd, vs2, vector/scalar/immediate source, v0` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vmerge.vxm` | `bit-preserving` | `exact-integer` |

### `mask-scan`（2）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vcpop.m` | `rd, mask vs2` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `not-applicable` | `require-zero` | 否 | 否 | `vcpop.m` | `mask-bit` | `exact-integer` |
| `vfirst.m` | `rd, mask vs2` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `not-applicable` | `require-zero` | 否 | 否 | `vfirst.m` | `mask-bit` | `exact-integer` |

### `memory-fof-load`（1）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vle8ff.v` | `vd, (rs1)` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vle8ff.v` | `not-applicable` | `not-applicable` |

### `memory-load`（4）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vle16.v` | `vd, (rs1)[, v0.t]` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 否 | 否 | `vle16.v` | `not-applicable` | `not-applicable` |
| `vle32.v` | `vd, (rs1)[, v0.t]` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 否 | 否 | `vle32.v` | `not-applicable` | `not-applicable` |
| `vle64.v` | `vd, (rs1)[, v0.t]` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 否 | 否 | `vle64.v` | `not-applicable` | `not-applicable` |
| `vle8.v` | `vd, (rs1)[, v0.t]` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 否 | 否 | `vle8.v` | `not-applicable` | `not-applicable` |

### `memory-load-indexed`（2）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vluxei16.v` | `vd, (rs1), index vs2` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vluxei16.v` | `unsigned-byte-index` | `not-applicable` |
| `vluxei64.v` | `vd, (rs1), index vs2` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vluxei64.v` | `unsigned-byte-index` | `not-applicable` |

### `memory-load-strided`（4）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vlse16.v` | `vd, (rs1), rs2` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vlse16.v` | `signed-byte-stride` | `not-applicable` |
| `vlse32.v` | `vd, (rs1), rs2` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vlse32.v` | `signed-byte-stride` | `not-applicable` |
| `vlse64.v` | `vd, (rs1), rs2[, v0.t]` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 否 | 否 | `vlse64.v` | `signed-byte-stride` | `not-applicable` |
| `vlse8.v` | `vd, (rs1), rs2` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vlse8.v` | `signed-byte-stride` | `not-applicable` |

### `memory-mask-store`（1）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vsm.v` | `mask vs3, (rs1)` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `not-applicable` | `require-zero` | 否 | 是 | `vsm.v` | `mask-bit` | `exact-integer` |

### `memory-segment-load`（4）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vlseg2e32.v` | `first vreg, (rs1)` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vlseg2e32.v` | `not-applicable` | `not-applicable` |
| `vlseg2e64.v` | `first vreg, (rs1)` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vlseg2e64.v` | `not-applicable` | `not-applicable` |
| `vlsseg2e32.v` | `first vreg, (rs1), rs2` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vlsseg2e32.v` | `not-applicable` | `not-applicable` |
| `vlsseg2e64.v` | `first vreg, (rs1), rs2` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 否 | 否 | `vlsseg2e64.v` | `not-applicable` | `not-applicable` |

### `memory-segment-store`（5）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vsseg2e32.v` | `first vreg, (rs1)` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `not-applicable` | `require-zero` | 否 | 否 | `vsseg2e32.v` | `not-applicable` | `not-applicable` |
| `vsseg2e64.v` | `first vreg, (rs1)` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `not-applicable` | `require-zero` | 否 | 否 | `vsseg2e64.v` | `not-applicable` | `not-applicable` |
| `vsseg4e64.v` | `first vreg, (rs1)` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `not-applicable` | `require-zero` | 否 | 否 | `vsseg4e64.v` | `not-applicable` | `not-applicable` |
| `vssseg2e32.v` | `first vreg, (rs1), rs2` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `not-applicable` | `require-zero` | 否 | 否 | `vssseg2e32.v` | `not-applicable` | `not-applicable` |
| `vssseg2e64.v` | `first vreg, (rs1), rs2` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `not-applicable` | `require-zero` | 否 | 否 | `vssseg2e64.v` | `not-applicable` | `not-applicable` |

### `memory-store`（4）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vse16.v` | `vs3, (rs1)[, v0.t]` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `not-applicable` | `require-zero` | 否 | 否 | `vse16.v` | `not-applicable` | `not-applicable` |
| `vse32.v` | `vs3, (rs1)[, v0.t]` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `not-applicable` | `require-zero` | 否 | 否 | `vse32.v` | `not-applicable` | `not-applicable` |
| `vse64.v` | `vs3, (rs1)[, v0.t]` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `not-applicable` | `require-zero` | 否 | 否 | `vse64.v` | `not-applicable` | `not-applicable` |
| `vse8.v` | `vs3, (rs1)[, v0.t]` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `not-applicable` | `require-zero` | 否 | 否 | `vse8.v` | `not-applicable` | `not-applicable` |

### `memory-store-strided`（4）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vsse16.v` | `vs3, (rs1), rs2` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `not-applicable` | `require-zero` | 否 | 否 | `vsse16.v` | `signed-byte-stride` | `not-applicable` |
| `vsse32.v` | `vs3, (rs1), rs2[, v0.t]` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `not-applicable` | `require-zero` | 否 | 否 | `vsse32.v` | `signed-byte-stride` | `not-applicable` |
| `vsse64.v` | `vs3, (rs1), rs2[, v0.t]` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `not-applicable` | `require-zero` | 否 | 否 | `vsse64.v` | `signed-byte-stride` | `not-applicable` |
| `vsse8.v` | `vs3, (rs1), rs2` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `not-applicable` | `require-zero` | 否 | 否 | `vsse8.v` | `signed-byte-stride` | `not-applicable` |

### `slide`（5）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vslide1down.vx` | `vd, vs2, rs1` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vslide1down.vx` | `unsigned-offset` | `exact-integer` |
| `vslide1up.vx` | `non-overlapping vd, vs2, rs1` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vslide1up.vx` | `bit-preserving` | `exact-integer` |
| `vslidedown.vi` | `vd, vs2, uimm5[, v0.t]` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `v0-only` | `undisturbed` | `require-zero` | 是 | 否 | `vslidedown.vi` | `unsigned-offset` | `exact-integer` |
| `vslidedown.vx` | `vd, vs2, rs1` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vslidedown.vx` | `unsigned-offset` | `exact-integer` |
| `vslideup.vi` | `vd, vs2, uimm5` | e8/e16/e32/e64 | mf8/mf4/mf2/m1/m2/m4/m8 | `forbidden` | `undisturbed` | `require-zero` | 是 | 否 | `vslideup.vi` | `unsigned-offset` | `exact-integer` |

### `whole-register-load`（14）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vl1r.v` | `vd, (rs1)` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `require-zero` | 否 | 是 | `vl1r.v` | `bit-preserving` | `not-applicable` |
| `vl1re16.v` | `vd, (rs1)` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `require-zero` | 否 | 是 | `vl1re16.v` | `bit-preserving` | `not-applicable` |
| `vl1re32.v` | `vd, (rs1)` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `require-zero` | 否 | 是 | `vl1re32.v` | `bit-preserving` | `not-applicable` |
| `vl1re64.v` | `vd, (rs1)` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `require-zero` | 否 | 是 | `vl1re64.v` | `bit-preserving` | `not-applicable` |
| `vl2r.v` | `vd, (rs1)` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `require-zero` | 否 | 是 | `vl2r.v` | `bit-preserving` | `not-applicable` |
| `vl2re16.v` | `vd, (rs1)` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `require-zero` | 否 | 是 | `vl2re16.v` | `bit-preserving` | `not-applicable` |
| `vl2re32.v` | `vd, (rs1)` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `require-zero` | 否 | 是 | `vl2re32.v` | `bit-preserving` | `not-applicable` |
| `vl4r.v` | `vd, (rs1)` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `require-zero` | 否 | 是 | `vl4r.v` | `bit-preserving` | `not-applicable` |
| `vl4re16.v` | `vd, (rs1)` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `require-zero` | 否 | 是 | `vl4re16.v` | `bit-preserving` | `not-applicable` |
| `vl4re32.v` | `vd, (rs1)` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `require-zero` | 否 | 是 | `vl4re32.v` | `bit-preserving` | `not-applicable` |
| `vl4re64.v` | `vd, (rs1)` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `require-zero` | 否 | 是 | `vl4re64.v` | `bit-preserving` | `not-applicable` |
| `vl8r.v` | `vd, (rs1)` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `require-zero` | 否 | 是 | `vl8r.v` | `bit-preserving` | `not-applicable` |
| `vl8re32.v` | `vd, (rs1)` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `require-zero` | 否 | 是 | `vl8re32.v` | `bit-preserving` | `not-applicable` |
| `vl8re64.v` | `vd, (rs1)` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `require-zero` | 否 | 是 | `vl8re64.v` | `bit-preserving` | `not-applicable` |

### `whole-register-move`（4）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vmv1r.v` | `vd, vs2` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `require-zero` | 否 | 是 | `vmv1r.v` | `bit-preserving` | `not-applicable` |
| `vmv2r.v` | `vd, vs2` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `require-zero` | 否 | 是 | `vmv2r.v` | `bit-preserving` | `not-applicable` |
| `vmv4r.v` | `vd, vs2` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `require-zero` | 否 | 是 | `vmv4r.v` | `bit-preserving` | `not-applicable` |
| `vmv8r.v` | `vd, vs2` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `require-zero` | 否 | 是 | `vmv8r.v` | `bit-preserving` | `not-applicable` |

### `whole-register-store`（4）

| opcode | 合法 operand form | SEW | LMUL | mask | tail | vstart | 旧 vd | vtype 无关 | 目标 mnemonic | 有符号性 | 舍入 |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| `vs1r.v` | `vs3, (rs1)` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `require-zero` | 否 | 是 | `vs1r.v` | `bit-preserving` | `not-applicable` |
| `vs2r.v` | `vs3, (rs1)` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `require-zero` | 否 | 是 | `vs2r.v` | `bit-preserving` | `not-applicable` |
| `vs4r.v` | `vs3, (rs1)` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `require-zero` | 否 | 是 | `vs4r.v` | `bit-preserving` | `not-applicable` |
| `vs8r.v` | `vs3, (rs1)` | 指令内决定/不依赖 | 指令内决定/不依赖 | `forbidden` | `not-applicable` | `require-zero` | 否 | 是 | `vs8r.v` | `bit-preserving` | `not-applicable` |

## 证据边界

- 本表证明 opcode 已注册、静态 form/能力字段存在且 dispatcher 可找到结构化 lowerer。
- pytest 与目标汇编器通过，只能分别证明主机结构/流程回归和目标汇编语法可接受。
- 算术、mask、tail、`vstart`、迁移状态和性能必须由相应 RISC-V/QEMU/真机差分验证证明。
