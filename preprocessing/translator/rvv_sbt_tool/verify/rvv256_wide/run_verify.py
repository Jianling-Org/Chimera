#!/usr/bin/env python3
"""为 RVV256 默认/宽优化路径生成、构建并运行目标语义差分用例。"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import shutil
import subprocess
import sys


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
ARTIFACT_ROOT = HERE / "artifacts"
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "src"))

from riscv.frontend.parser import AsmParser  # noqa: E402
from riscv.extensions.rvv.runtime.contract import RVV1024_TO_RVV256  # noqa: E402
from rvv_sbt_rvv import translate  # noqa: E402
from riscv.extensions.rvv.backends.rvv256.specs import RVV256_SAME_WIDTH_OPCODES  # noqa: E402


@dataclass(frozen=True)
class Case:
    name: str
    command: str
    vtype: str
    c_source: str
    # 仅 vfwmul.vf e16 需要 Zvfh；其他用例保持原 rv64gcv，便于在较旧工具链
    # 上继续执行不依赖半精度扩展的语义门禁。
    march: str = "rv64gcv"
    # True 表示当前默认宽 profile。设为 False 的 case 专门验证
    # ``--conservative`` profile 的 native mask、whole transfer 和 direct-vlm
    # 优化；它们仍使用同一 simulated_cpu_state ABI 与 C reference。
    wide_lmul: bool = True

    @property
    def directory(self) -> Path:
        return ARTIFACT_ROOT / self.name


_C_HEADER = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define STATE_SIZE 0x1040
#define VL_OFFSET 0x1020
#define VSTART_OFFSET 0x1000
#define VREG_OFFSET(n) ((n) * 128)
#define CANARY_SIZE 64

/* RVV1024→RVV256 新契约的状态符号；后续 C reference 继续使用短别名，
 * 以便本文件的状态初始化代码保持可读，同时让汇编与链接符号一致。 */
#define simulated_cpu_state {state_symbol}

struct state_fixture_layout {
    uint8_t before[CANARY_SIZE];
    uint8_t state[STATE_SIZE];
    uint8_t after[CANARY_SIZE];
};

struct state_fixture_layout state_fixture __attribute__((aligned(64)));
extern uint8_t simulated_cpu_state[STATE_SIZE];
/* 让目标汇编仍按 ABI 名称取状态基址，同时在 C reference 中保留前后 canary。 */
__asm__(".globl {state_symbol}\n"
        ".set {state_symbol}, state_fixture + 64\n");

static uint8_t expected_state[STATE_SIZE];

/* RVV vfmin/vfmax 的 reference 规则：单个 NaN 返回另一个操作数，两个 NaN
 * 返回 canonical NaN；两个零需要保留 IEEE 754 规定的符号方向。 */
static float chimera_ref_fminf(float lhs, float rhs) {
    int lhs_nan = __builtin_isnan(lhs);
    int rhs_nan = __builtin_isnan(rhs);
    if (lhs_nan) return rhs_nan ? __builtin_nanf("") : rhs;
    if (rhs_nan) return lhs;
    if (lhs == 0.0f && rhs == 0.0f)
        return __builtin_signbit(lhs) ? lhs : rhs;
    return lhs < rhs ? lhs : rhs;
}

static float chimera_ref_fmaxf(float lhs, float rhs) {
    int lhs_nan = __builtin_isnan(lhs);
    int rhs_nan = __builtin_isnan(rhs);
    if (lhs_nan) return rhs_nan ? __builtin_nanf("") : rhs;
    if (rhs_nan) return lhs;
    if (lhs == 0.0f && rhs == 0.0f)
        return __builtin_signbit(lhs) ? rhs : lhs;
    return lhs > rhs ? lhs : rhs;
}

static double chimera_ref_fmind(double lhs, double rhs) {
    int lhs_nan = __builtin_isnan(lhs);
    int rhs_nan = __builtin_isnan(rhs);
    if (lhs_nan) return rhs_nan ? __builtin_nan("") : rhs;
    if (rhs_nan) return lhs;
    if (lhs == 0.0 && rhs == 0.0)
        return __builtin_signbit(lhs) ? lhs : rhs;
    return lhs < rhs ? lhs : rhs;
}

static double chimera_ref_fmaxd(double lhs, double rhs) {
    int lhs_nan = __builtin_isnan(lhs);
    int rhs_nan = __builtin_isnan(rhs);
    if (lhs_nan) return rhs_nan ? __builtin_nan("") : rhs;
    if (rhs_nan) return lhs;
    if (lhs == 0.0 && rhs == 0.0)
        return __builtin_signbit(lhs) ? rhs : lhs;
    return lhs > rhs ? lhs : rhs;
}

/* RVV vdiv.vx 的 reference 规则：除数为零时结果为全 1，最小负数除以
 * -1 时保留最小负数。先在 int64_t 中显式处理这两个特殊分支，避免 C
 * 的除零和有符号溢出未定义行为污染 RVV256 宽路径的差分结果。 */
static int64_t chimera_ref_sdiv(int64_t numerator, int64_t denominator,
                                unsigned sew) {
    int64_t minimum;
    switch (sew) {
    case 8:
        minimum = -128;
        break;
    case 16:
        minimum = -32768;
        break;
    case 32:
        minimum = -2147483647 - 1;
        break;
    case 64:
        minimum = INT64_MIN;
        break;
    default:
        return 0;
    }
    if (denominator == 0) return -1;
    if (numerator == minimum && denominator == -1) return minimum;
    return numerator / denominator;
}

static void init_state(uint64_t vl) {
    memset(state_fixture.before, 0xC3, CANARY_SIZE);
    memset(state_fixture.after, 0x3C, CANARY_SIZE);
    memset(simulated_cpu_state, 0xA5, STATE_SIZE);
    memcpy(expected_state, simulated_cpu_state, STATE_SIZE);
    *(uint64_t *)(simulated_cpu_state + VL_OFFSET) = vl;
    *(uint64_t *)(expected_state + VL_OFFSET) = vl;
    *(uint64_t *)(simulated_cpu_state + VSTART_OFFSET) = 0;
    *(uint64_t *)(expected_state + VSTART_OFFSET) = 0;
}

static int check_state(void) {
    for (size_t i = 0; i < CANARY_SIZE; ++i) {
        if (state_fixture.before[i] != 0xC3 || state_fixture.after[i] != 0x3C) {
            fprintf(stderr, "state canary mismatch at %zu\n", i);
            return 1;
        }
    }
    for (size_t i = 0; i < STATE_SIZE; ++i) {
        if (simulated_cpu_state[i] != expected_state[i]) {
            fprintf(stderr, "state mismatch at 0x%zx: got=%02x expected=%02x\n",
                    i, simulated_cpu_state[i], expected_state[i]);
            return 1;
        }
    }
    return 0;
}

static void init_mask(uint64_t vl) {
    uint8_t *mask = simulated_cpu_state + VREG_OFFSET(0);
    uint8_t *expected_mask = expected_state + VREG_OFFSET(0);
    size_t bytes = (size_t)((vl + 7) / 8);
    memset(mask, 0, bytes);
    /* 使用非平凡的 11010... 模式，同时覆盖命中、未命中和跨字节边界。 */
    for (size_t i = 0; i < vl; ++i) {
        if ((i % 5) != 2 && (i % 5) != 4) mask[i / 8] |= (uint8_t)(1u << (i % 8));
    }
    memcpy(expected_mask, mask, bytes);
}

static int mask_enabled(size_t index) {
    const uint8_t *mask = simulated_cpu_state + VREG_OFFSET(0);
    return (mask[index / 8] >> (index % 8)) & 1;
}
'''.replace("{state_symbol}", RVV1024_TO_RVV256.state_symbol)


def _call_or_benchmark(call: str, name: str) -> str:
    """语义模式执行一次；BENCHMARK_ITERATIONS 模式记录每次调用 cycle。"""
    return f'''
#ifndef BENCHMARK_ITERATIONS
    {call}
#else
    uint64_t cycle_begin, cycle_end;
    __asm__ volatile("rdcycle %0" : "=r"(cycle_begin));
    for (size_t iteration = 0; iteration < BENCHMARK_ITERATIONS; ++iteration) {{
        {call}
    }}
    __asm__ volatile("rdcycle %0" : "=r"(cycle_end));
    printf("{name} cycles_per_call=%.3f iterations=%d\\n",
           (double)(cycle_end - cycle_begin) / BENCHMARK_ITERATIONS,
           BENCHMARK_ITERATIONS);
    return 0;
#endif'''


def _integer_vadd_source(
    sew: int, vl: int, vd: int, vs1: int, vs2: int, *, masked: bool = False
) -> str:
    ctype = {8: "uint8_t", 16: "uint16_t", 32: "uint32_t", 64: "uint64_t"}[sew]
    return _C_HEADER + f'''
extern void translated_func(void);
int main(void) {{
    init_state({vl});
    {"init_mask(" + str(vl) + ");" if masked else ""}
    {ctype} *vs1 = ({ctype} *)(simulated_cpu_state + VREG_OFFSET({vs1}));
    {ctype} *vs2 = ({ctype} *)(simulated_cpu_state + VREG_OFFSET({vs2}));
    {ctype} *expected = ({ctype} *)(expected_state + VREG_OFFSET({vd}));
    {ctype} *expected_vs1 = ({ctype} *)(expected_state + VREG_OFFSET({vs1}));
    {ctype} *expected_vs2 = ({ctype} *)(expected_state + VREG_OFFSET({vs2}));
    for (size_t i = 0; i < {vl}; ++i) {{
        vs1[i] = ({ctype})(i + 3);
        vs2[i] = ({ctype})(i * 5 + 1);
        expected_vs1[i] = vs1[i];
        expected_vs2[i] = vs2[i];
        if ({"mask_enabled(i)" if masked else "1"})
            expected[i] = ({ctype})(vs1[i] + vs2[i]);
    }}
{_call_or_benchmark("translated_func();", f"vadd_e{sew}")}
    return check_state();
}}
'''


def _float_source(
    opcode: str,
    sew: int,
    vl: int,
    vd: int,
    vs1: int | None,
    vs2: int,
    *,
    masked: bool = False,
) -> str:
    ctype = "float" if sew == 32 else "double"
    prototype = f"extern void translated_func({ctype});" if opcode.endswith(".vf") else "extern void translated_func(void);"
    call = "translated_func(2.0);" if opcode.endswith(".vf") else "translated_func();"
    vs1_setup = ""
    expression = ""
    if opcode == "vfmacc.vf":
        expression = "vd[i] + 2.0 * src2[i]"
    elif opcode == "vfnmsac.vf":
        expression = "vd[i] - 2.0 * src2[i]"
    elif opcode == "vfmul.vf":
        expression = "2.0 * src2[i]"
    else:
        vs1_setup = f'''    {ctype} *src1 = ({ctype} *)(simulated_cpu_state + VREG_OFFSET({vs1}));
        src1[i] = ({ctype})(i + 2);
        expected_src1[i] = src1[i];'''
        expression = "vd[i] + src1[i] * src2[i]"
    return _C_HEADER + f'''
{prototype}
int main(void) {{
    init_state({vl});
    {"init_mask(" + str(vl) + ");" if masked else ""}
    {ctype} *vd = ({ctype} *)(simulated_cpu_state + VREG_OFFSET({vd}));
    {ctype} *src2 = ({ctype} *)(simulated_cpu_state + VREG_OFFSET({vs2}));
    {ctype} *expected = ({ctype} *)(expected_state + VREG_OFFSET({vd}));
    {ctype} *expected_src2 = ({ctype} *)(expected_state + VREG_OFFSET({vs2}));
    {f'''{ctype} *expected_src1 = ({ctype} *)(expected_state + VREG_OFFSET({vs1}));''' if vs1 is not None else ''}
    for (size_t i = 0; i < {vl}; ++i) {{
        vd[i] = ({ctype})(i + 1);
        expected[i] = vd[i];
        src2[i] = ({ctype})(i + 3);
        expected_src2[i] = src2[i];
{vs1_setup}
        if ({"mask_enabled(i)" if masked else "1"})
            expected[i] = ({ctype})({expression});
    }}
{_call_or_benchmark(call, opcode.replace('.', '_'))}
    return check_state();
}}
'''


_FIRST_BATCH_FLOAT_OPCODES = frozenset(
    opcode for opcode in RVV256_SAME_WIDTH_OPCODES if opcode.startswith("vf")
)
_FIRST_BATCH_UNARY_OPCODES = frozenset({"vnot.v", "vfabs.v", "vfneg.v"})
_FIRST_BATCH_E8_OPCODES = frozenset(
    {
        "vand.vi",
        "vand.vv",
        "vand.vx",
        "vandn.vv",
        "vor.vi",
        "vor.vv",
        "vnot.v",
        "vxor.vv",
        "vsll.vi",
        "vsll.vv",
        "vsll.vx",
        "vsra.vi",
        "vsrl.vi",
        "vsrl.vv",
        "vsrl.vx",
    }
)


def _same_width_command(opcode: str) -> str:
    """构造首期同宽 reference case 使用的合法源指令。"""

    if opcode in _FIRST_BATCH_UNARY_OPCODES:
        return f"{opcode} v8, v16"
    if opcode.endswith(".vv"):
        return f"{opcode} v8, v16, v24"
    if opcode.endswith(".vi"):
        return f"{opcode} v8, v16, 3"
    if opcode.endswith(".vf"):
        return f"{opcode} v8, v16, fa0"
    if opcode.endswith(".vx"):
        return f"{opcode} v8, v16, a0"
    raise ValueError(f"未定义首期同宽操作数形式: {opcode}")


def _same_width_c_types(sew: int) -> tuple[str, str]:
    """返回无符号和有符号的 C 标量类型名。"""

    return (
        {8: "uint8_t", 16: "uint16_t", 32: "uint32_t", 64: "uint64_t"}[sew],
        {8: "int8_t", 16: "int16_t", 32: "int32_t", 64: "int64_t"}[sew],
    )


def _same_width_integer_expression(opcode: str, value_type: str, sew: int) -> str:
    """返回整数同宽指令的 C reference 表达式。"""

    shift_mask = sew - 1
    if opcode == "vand.vv":
        return f"({value_type})(src2[i] & src1[i])"
    if opcode == "vand.vx":
        return f"({value_type})(src2[i] & scalar_value)"
    if opcode == "vand.vi":
        return f"({value_type})(src2[i] & ({value_type})3)"
    if opcode == "vandn.vv":
        return f"({value_type})(src2[i] & ({value_type})(~src1[i]))"
    if opcode == "vor.vv":
        return f"({value_type})(src2[i] | src1[i])"
    if opcode == "vor.vi":
        return f"({value_type})(src2[i] | ({value_type})3)"
    if opcode == "vxor.vv":
        return f"({value_type})(src2[i] ^ src1[i])"
    if opcode == "vnot.v":
        return f"({value_type})(~src2[i])"
    if opcode == "vsub.vv":
        return f"({value_type})(src2[i] - src1[i])"
    if opcode == "vsub.vx":
        return f"({value_type})(src2[i] - scalar_value)"
    if opcode == "vmax.vv":
        return f"(src2[i] > src1[i] ? src2[i] : src1[i])"
    if opcode == "vmaxu.vv":
        return f"(src2[i] > src1[i] ? src2[i] : src1[i])"
    if opcode == "vmul.vv":
        return f"({value_type})(src2[i] * src1[i])"
    if opcode == "vmul.vx":
        return f"({value_type})(src2[i] * scalar_value)"
    if opcode == "vdiv.vx":
        return (
            f"({value_type})chimera_ref_sdiv((int64_t)src2[i], "
            f"(int64_t)scalar_value, {sew})"
        )
    if opcode == "vsll.vv":
        return f"({value_type})(src2[i] << (src1[i] & {shift_mask}))"
    if opcode == "vsll.vx":
        return f"({value_type})(src2[i] << (scalar_value & {shift_mask}))"
    if opcode == "vsll.vi":
        return f"({value_type})(src2[i] << (3 & {shift_mask}))"
    if opcode == "vsrl.vv":
        return f"({value_type})(src2[i] >> (src1[i] & {shift_mask}))"
    if opcode == "vsrl.vx":
        return f"({value_type})(src2[i] >> (scalar_value & {shift_mask}))"
    if opcode == "vsrl.vi":
        return f"({value_type})(src2[i] >> (3 & {shift_mask}))"
    if opcode == "vsra.vi":
        return f"({value_type})(src2[i] >> (3 & {shift_mask}))"
    raise ValueError(f"未定义整数 reference 表达式: {opcode}")


def _same_width_float_expression(opcode: str, ctype: str) -> str:
    """返回浮点同宽指令的 C reference 表达式。"""

    scalar = "2.0f" if ctype == "float" else "2.0"
    if opcode == "vfabs.v":
        builtin = "__builtin_fabsf" if ctype == "float" else "__builtin_fabs"
        return f"{builtin}(src2[i])"
    if opcode == "vfneg.v":
        return "-src2[i]"
    if opcode == "vfadd.vv":
        return "src2[i] + src1[i]"
    if opcode == "vfadd.vf":
        return f"src2[i] + {scalar}"
    if opcode == "vfsub.vv":
        return "src2[i] - src1[i]"
    if opcode == "vfsub.vf":
        return f"src2[i] - {scalar}"
    if opcode == "vfrsub.vf":
        return f"{scalar} - src2[i]"
    if opcode == "vfmul.vv":
        return "src2[i] * src1[i]"
    if opcode == "vfdiv.vv":
        return "src2[i] / src1[i]"
    if opcode == "vfmax.vv":
        helper = "chimera_ref_fmaxf" if ctype == "float" else "chimera_ref_fmaxd"
        return f"{helper}(src2[i], src1[i])"
    if opcode == "vfmin.vv":
        helper = "chimera_ref_fminf" if ctype == "float" else "chimera_ref_fmind"
        return f"{helper}(src2[i], src1[i])"
    raise ValueError(f"未定义浮点 reference 表达式: {opcode}")


def _same_width_source(
    opcode: str, sew: int, vl: int, *, scalar_value: int = 3
) -> str:
    """
    构造首期 33 条无掩码同宽指令的 C reference。

    整数用小范围值覆盖溢出、移位和有符号分支；vfmin/vfmax 额外放入
    零、无穷和 NaN，以检查基础 IEEE 754 边界。其余浮点算术使用有限值，
    避免把不同硬件的 NaN payload 差异误判成向量宽化问题。
    """

    is_float = opcode in _FIRST_BATCH_FLOAT_OPCODES
    operand_form = "unary" if opcode in _FIRST_BATCH_UNARY_OPCODES else (
        "vv" if opcode.endswith(".vv") else "scalar"
    )
    if is_float:
        ctype = "float" if sew == 32 else "double"
        value_type = ctype
        scalar_declaration = ""
        call = "translated_func(2.0f);" if opcode.endswith(".vf") and sew == 32 else (
            "translated_func(2.0);" if opcode.endswith(".vf") else "translated_func();"
        )
        prototype = (
            f"extern void translated_func({ctype});"
            if opcode.endswith(".vf")
            else "extern void translated_func(void);"
        )
        expression = _same_width_float_expression(opcode, ctype)
        if opcode in {"vfmax.vv", "vfmin.vv"}:
            finite_suffix = "f" if ctype == "float" else ""
            inf_function = f"__builtin_inf{finite_suffix}"
            nan_function = f"__builtin_nan{finite_suffix}"
            src2_setup = f"""        if (i % 6 == 0) src2[i] = -0.0{finite_suffix};
        else if (i % 6 == 1) src2[i] = {inf_function}();
        else if (i % 6 == 2) src2[i] = -{inf_function}();
        else if (i % 6 == 3) src2[i] = {nan_function}(\"\");
        else src2[i] = ({ctype})(i - 9);"""
            src1_setup = f"""        if (i % 6 == 0) src1[i] = 0.0{finite_suffix};
        else if (i % 6 == 1) src1[i] = 1.0{finite_suffix};
        else if (i % 6 == 2) src1[i] = {inf_function}();
        else if (i % 6 == 3) src1[i] = {nan_function}(\"\");
        else src1[i] = ({ctype})(3 - (int)i);"""
        else:
            src2_setup = f"src2[i] = ({ctype})((int)(i % 17) - 8);"
            src1_setup = f"src1[i] = ({ctype})((int)(i % 13) + 2);"
    else:
        unsigned_type, signed_type = _same_width_c_types(sew)
        signed_operation = opcode in {"vdiv.vx", "vsra.vi", "vmax.vv"}
        value_type = signed_type if signed_operation else unsigned_type
        scalar_declaration = (
            f"    {value_type} scalar_value = ({value_type}){scalar_value};"
        )
        call = (
            f"translated_func({scalar_value});"
            if opcode.endswith(".vx")
            else "translated_func();"
        )
        prototype = (
            "extern void translated_func(long);"
            if opcode.endswith(".vx")
            else "extern void translated_func(void);"
        )
        expression = _same_width_integer_expression(opcode, value_type, sew)
        if opcode == "vdiv.vx" and scalar_value in (0, -1):
            # 两个独立 case 分别锁定除零和最小负数/-1 溢出规则，并同时
            # 放入正负普通值，防止只验证特殊分支而漏掉符号方向。
            minimum = {
                8: "-128",
                16: "-32768",
                32: "(-2147483647 - 1)",
                64: "INT64_MIN",
            }[sew]
            maximum = {
                8: "127",
                16: "32767",
                32: "2147483647",
                64: "INT64_MAX",
            }[sew]
            src2_setup = f"""if (i == 0) src2[i] = ({value_type})({minimum});
        else if (i == 1) src2[i] = ({value_type})({maximum});
        else if (i == 2) src2[i] = ({value_type})(-7);
        else if (i == 3) src2[i] = ({value_type})7;
        else src2[i] = ({value_type})(i % 11);"""
        else:
            src2_setup = (
                f"src2[i] = ({value_type})((int)(i % 61) - 30);"
                if signed_operation
                else f"src2[i] = ({value_type})(i * 5 + 1);"
            )
        src1_setup = f"src1[i] = ({value_type})(i * 3 + 2);"

    source1_declaration = (
        f"    {value_type} *src1 = ({value_type} *)(simulated_cpu_state + VREG_OFFSET(24));\n"
        f"    {value_type} *expected_src1 = ({value_type} *)(expected_state + VREG_OFFSET(24));\n"
        if operand_form == "vv"
        else ""
    )
    source1_setup_line = ""
    source1_copy_line = ""
    if operand_form == "vv":
        source1_setup_line = f"        {src1_setup}"
        source1_copy_line = "        expected_src1[i] = src1[i];"

    return _C_HEADER + f'''
{prototype}
int main(void) {{
    init_state({vl});
{scalar_declaration}
    {value_type} *src2 = ({value_type} *)(simulated_cpu_state + VREG_OFFSET(16));
    {value_type} *expected_src2 = ({value_type} *)(expected_state + VREG_OFFSET(16));
    {value_type} *expected = ({value_type} *)(expected_state + VREG_OFFSET(8));
{source1_declaration.rstrip()}
    for (size_t i = 0; i < {vl}; ++i) {{
        {src2_setup}
        expected_src2[i] = src2[i];
{source1_setup_line}
{source1_copy_line}
        expected[i] = ({value_type})({expression});
    }}
{_call_or_benchmark(call, opcode.replace('.', '_'))}
    return check_state();
}}
'''


def _first_batch_cases() -> dict[str, Case]:
    """为首期每个 opcode 注册一个目标 reference/candidate case。"""

    cases: dict[str, Case] = {}
    for opcode in sorted(RVV256_SAME_WIDTH_OPCODES):
        if opcode in _FIRST_BATCH_FLOAT_OPCODES:
            sew, lmul, vl = 32, 8, 193
        elif opcode in _FIRST_BATCH_E8_OPCODES:
            sew, lmul, vl = 8, 1, 97
        else:
            sew, lmul, vl = 32, 8, 193
        name = f"wide_{opcode.replace('.', '_')}_e{sew}_m{lmul}"
        cases[name] = Case(
            name,
            _same_width_command(opcode),
            f"sew={sew},lmul={lmul}",
            _same_width_source(opcode, sew, vl),
        )

    # vdiv.vx 的异常边界不与普通整数算术共用一份输入：RVV 规定除零
    # 返回全 1，最小负数除以 -1 保持最小负数。分别使用 e32/e64，确保
    # C reference 和目标宽路径都实际经过这两个分支。
    edge_cases = (
        ("wide_vdiv_vx_divzero_e32_m8", 32, 8, 193, 0),
        ("wide_vdiv_vx_min_negative_e64_m4", 64, 4, 97, -1),
    )
    for name, sew, lmul, vl, scalar_value in edge_cases:
        cases[name] = Case(
            name,
            _same_width_command("vdiv.vx"),
            f"sew={sew},lmul={lmul}",
            _same_width_source("vdiv.vx", sew, vl, scalar_value=scalar_value),
        )
    return cases


def _unit_memory_source(
    load: bool, sew: int, vl: int, vreg: int, *, masked: bool = False
) -> str:
    ctype = {8: "uint8_t", 16: "uint16_t", 32: "uint32_t", 64: "uint64_t"}[sew]
    setup = ""
    expected = ""
    if load:
        setup = f"memory[i] = ({ctype})(i * 7 + 9); expected_memory[i] = memory[i];"
        expected = f"if ({'mask_enabled(i)' if masked else '1'}) expected_state_data[i] = memory[i];"
    else:
        setup = f"state[i] = ({ctype})(i * 7 + 9); expected_state_data[i] = state[i];"
        expected = f"if ({'mask_enabled(i)' if masked else '1'}) expected_memory[i] = state[i];"
    return _C_HEADER + f'''
extern void translated_func({ctype} *);
int main(void) {{
    init_state({vl});
    {"init_mask(" + str(vl) + ");" if masked else ""}
    {ctype} memory[{vl + 8}], expected_memory[{vl + 8}];
    memset(memory, 0x3C, sizeof(memory));
    memcpy(expected_memory, memory, sizeof(memory));
    {ctype} *state = ({ctype} *)(simulated_cpu_state + VREG_OFFSET({vreg}));
    {ctype} *expected_state_data = ({ctype} *)(expected_state + VREG_OFFSET({vreg}));
    for (size_t i = 0; i < {vl}; ++i) {{ {setup} {expected} }}
{_call_or_benchmark("translated_func(memory);", f"{'vle' if load else 'vse'}{sew}")}
    if (check_state()) return 1;
    if (memcmp(memory, expected_memory, sizeof(memory)) != 0) {{
        fprintf(stderr, "unit memory mismatch\\n"); return 1;
    }}
    return 0;
}}
'''


def _strided_source(
    load: bool,
    sew: int,
    vl: int,
    vreg: int,
    stride: int,
    *,
    masked: bool = False,
) -> str:
    ctype = {32: "uint32_t", 64: "uint64_t"}[sew]
    stride_elems = abs(stride) // (sew // 8)
    base_expr = f"memory + {(vl - 1) * stride_elems}" if stride < 0 else "memory"
    setup = ""
    expected = ""
    if load:
        setup = f"base[(long)i * ({stride // (sew // 8)})] = ({ctype})(i * 11 + 5); expected_memory[(base - memory) + (long)i * ({stride // (sew // 8)})] = base[(long)i * ({stride // (sew // 8)})];"
        expected = f"if ({'mask_enabled(i)' if masked else '1'}) expected_state_data[i] = base[(long)i * ({stride // (sew // 8)})];"
    else:
        setup = f"state[i] = ({ctype})(i * 11 + 5); expected_state_data[i] = state[i];"
        expected = f"if ({'mask_enabled(i)' if masked else '1'}) expected_memory[(base - memory) + (long)i * ({stride // (sew // 8)})] = state[i];"
    return _C_HEADER + f'''
extern void translated_func({ctype} *, long);
int main(void) {{
    init_state({vl});
    {"init_mask(" + str(vl) + ");" if masked else ""}
    {ctype} memory[{vl * stride_elems + 16}], expected_memory[{vl * stride_elems + 16}];
    memset(memory, 0x3C, sizeof(memory));
    memcpy(expected_memory, memory, sizeof(memory));
    {ctype} *base = {base_expr};
    {ctype} *state = ({ctype} *)(simulated_cpu_state + VREG_OFFSET({vreg}));
    {ctype} *expected_state_data = ({ctype} *)(expected_state + VREG_OFFSET({vreg}));
    for (size_t i = 0; i < {vl}; ++i) {{ {setup} {expected} }}
{_call_or_benchmark(f"translated_func(base, {stride});", f"{'vlse' if load else 'vsse'}{sew}")}
    if (check_state()) return 1;
    if (memcmp(memory, expected_memory, sizeof(memory)) != 0) {{
        fprintf(stderr, "strided memory mismatch\\n"); return 1;
    }}
    return 0;
}}
'''


def _whole_move_source(nf: int, vd: int, vs2: int) -> str:
    total = nf * 128
    return _C_HEADER + f'''
extern void translated_func(void);
int main(void) {{
    init_state(0);
    for (size_t i = 0; i < {total}; ++i) {{
        simulated_cpu_state[VREG_OFFSET({vs2}) + i] = (uint8_t)(i * 13 + 7);
        expected_state[VREG_OFFSET({vs2}) + i] = simulated_cpu_state[VREG_OFFSET({vs2}) + i];
        expected_state[VREG_OFFSET({vd}) + i] = simulated_cpu_state[VREG_OFFSET({vs2}) + i];
    }}
{_call_or_benchmark("translated_func();", f"vmv{nf}r")}
    return check_state();
}}
'''


def _whole_memory_source(load: bool, nf: int, vreg: int) -> str:
    total = nf * 128
    setup = ""
    if load:
        setup = f'''
    for (size_t i = 0; i < {total}; ++i) {{
        memory[i] = (uint8_t)(i * 17 + 3);
        expected_memory[i] = memory[i];
        expected_state[VREG_OFFSET({vreg}) + i] = memory[i];
    }}'''
    else:
        setup = f'''
    for (size_t i = 0; i < {total}; ++i) {{
        simulated_cpu_state[VREG_OFFSET({vreg}) + i] = (uint8_t)(i * 17 + 3);
        expected_state[VREG_OFFSET({vreg}) + i] = simulated_cpu_state[VREG_OFFSET({vreg}) + i];
        expected_memory[i] = simulated_cpu_state[VREG_OFFSET({vreg}) + i];
    }}'''
    return _C_HEADER + f'''
extern void translated_func(uint8_t *);
int main(void) {{
    init_state(0);
    uint8_t memory[{total + 16}], expected_memory[{total + 16}];
    memset(memory, 0x3C, sizeof(memory));
    memcpy(expected_memory, memory, sizeof(memory));
{setup}
{_call_or_benchmark("translated_func(memory);", f"{'vl' if load else 'vs'}{nf}r")}
    if (check_state()) return 1;
    if (memcmp(memory, expected_memory, sizeof(memory)) != 0) {{
        fprintf(stderr, "whole memory mismatch\\n"); return 1;
    }}
    return 0;
}}
'''


def _vadd_vi_source(*, masked: bool) -> str:
    """e8,m2 immediate add，覆盖 256-bit mask 块和不完整尾字节。"""
    vl = 193
    return _C_HEADER + f'''
extern void translated_func(void);
int main(void) {{
    init_state({vl});
    {"init_mask(" + str(vl) + ");" if masked else ""}
    uint8_t *src = simulated_cpu_state + VREG_OFFSET(12);
    uint8_t *expected_src = expected_state + VREG_OFFSET(12);
    uint8_t *expected = expected_state + VREG_OFFSET(8);
    for (size_t i = 0; i < {vl}; ++i) {{
        src[i] = (uint8_t)(i * 7 + 1); expected_src[i] = src[i];
        if ({"mask_enabled(i)" if masked else "1"}) expected[i] = (uint8_t)(src[i] + 3);
    }}
{_call_or_benchmark("translated_func();", "vadd_vi_e8_m2")}
    return check_state();
}}
'''


def _vrsub_vi_source(*, masked: bool) -> str:
    """e8,m1 reverse-subtract，覆盖默认 direct-vlm 与标量尾部。"""
    vl = 97
    return _C_HEADER + f'''
extern void translated_func(void);
int main(void) {{
    init_state({vl});
    {"init_mask(" + str(vl) + ");" if masked else ""}
    uint8_t *src = simulated_cpu_state + VREG_OFFSET(12);
    uint8_t *expected_src = expected_state + VREG_OFFSET(12);
    uint8_t *expected = expected_state + VREG_OFFSET(8);
    for (size_t i = 0; i < {vl}; ++i) {{
        src[i] = (uint8_t)(i * 9 + 5); expected_src[i] = src[i];
        if ({"mask_enabled(i)" if masked else "1"}) expected[i] = (uint8_t)(3u - src[i]);
    }}
{_call_or_benchmark("translated_func();", "vrsub_vi_e8_m1")}
    return check_state();
}}
'''


def _vwmacc_vx_source(*, masked: bool) -> str:
    """e16->e32 signed widening MAC，目标状态跨两个 128B vreg 槽。"""
    vl = 61
    return _C_HEADER + f'''
extern void translated_func(long);
int main(void) {{
    init_state({vl});
    {"init_mask(" + str(vl) + ");" if masked else ""}
    int16_t *src = (int16_t *)(simulated_cpu_state + VREG_OFFSET(12));
    int16_t *expected_src = (int16_t *)(expected_state + VREG_OFFSET(12));
    int32_t *dst = (int32_t *)(simulated_cpu_state + VREG_OFFSET(8));
    int32_t *expected = (int32_t *)(expected_state + VREG_OFFSET(8));
    for (size_t i = 0; i < {vl}; ++i) {{
        src[i] = (int16_t)((int)i - 29); expected_src[i] = src[i];
        dst[i] = (int32_t)(i * 11 - 300); expected[i] = dst[i];
        if ({"mask_enabled(i)" if masked else "1"}) expected[i] += 3 * (int32_t)src[i];
    }}
{_call_or_benchmark("translated_func(3);", "vwmacc_vx_e16_m1")}
    return check_state();
}}
'''


def _vwadd_wv_source() -> str:
    vl = 61
    return _C_HEADER + f'''
extern void translated_func(void);
int main(void) {{
    init_state({vl});
    int32_t *wide = (int32_t *)(simulated_cpu_state + VREG_OFFSET(12));
    int32_t *expected_wide = (int32_t *)(expected_state + VREG_OFFSET(12));
    int16_t *narrow = (int16_t *)(simulated_cpu_state + VREG_OFFSET(16));
    int16_t *expected_narrow = (int16_t *)(expected_state + VREG_OFFSET(16));
    int32_t *expected = (int32_t *)(expected_state + VREG_OFFSET(8));
    for (size_t i = 0; i < {vl}; ++i) {{
        wide[i] = (int32_t)(i * 101 - 900); expected_wide[i] = wide[i];
        narrow[i] = (int16_t)((int)i - 17); expected_narrow[i] = narrow[i];
        expected[i] = wide[i] + (int32_t)narrow[i];
    }}
{_call_or_benchmark("translated_func();", "vwadd_wv_e16_m1")}
    return check_state();
}}
'''


def _vwredsum_source(*, masked: bool) -> str:
    vl = 61
    return _C_HEADER + f'''
extern void translated_func(void);
int main(void) {{
    init_state({vl});
    {"init_mask(" + str(vl) + ");" if masked else ""}
    int16_t *src = (int16_t *)(simulated_cpu_state + VREG_OFFSET(12));
    int16_t *expected_src = (int16_t *)(expected_state + VREG_OFFSET(12));
    int32_t *seed = (int32_t *)(simulated_cpu_state + VREG_OFFSET(16));
    int32_t *expected_seed = (int32_t *)(expected_state + VREG_OFFSET(16));
    int32_t *expected = (int32_t *)(expected_state + VREG_OFFSET(8));
    seed[0] = 1234; expected_seed[0] = seed[0];
    int32_t sum = seed[0];
    for (size_t i = 0; i < {vl}; ++i) {{
        src[i] = (int16_t)((int)i - 31); expected_src[i] = src[i];
        if ({"mask_enabled(i)" if masked else "1"}) sum += (int32_t)src[i];
    }}
    expected[0] = sum;
{_call_or_benchmark("translated_func();", "vwredsum_e16_m1")}
    return check_state();
}}
'''


def _vmseq_vi_source() -> str:
    vl = 97
    return _C_HEADER + f'''
extern void translated_func(void);
int main(void) {{
    init_state({vl});
    uint8_t *src = simulated_cpu_state + VREG_OFFSET(4);
    uint8_t *expected_src = expected_state + VREG_OFFSET(4);
    uint8_t *expected_mask = expected_state + VREG_OFFSET(1);
    for (size_t i = 0; i < {vl}; ++i) {{
        src[i] = (uint8_t)((i % 7) - 3); expected_src[i] = src[i];
        uint8_t bit = (uint8_t)(1u << (i % 8));
        if (src[i] == (uint8_t)-1) expected_mask[i / 8] |= bit;
        else expected_mask[i / 8] &= (uint8_t)~bit;
    }}
{_call_or_benchmark("translated_func();", "vmseq_vi")}
    return check_state();
}}
'''


def _vmor_source() -> str:
    vl = 173
    return _C_HEADER + f'''
extern void translated_func(void);
int main(void) {{
    init_state({vl});
    uint8_t *src2 = simulated_cpu_state + VREG_OFFSET(2);
    uint8_t *src1 = simulated_cpu_state + VREG_OFFSET(3);
    uint8_t *expected_src2 = expected_state + VREG_OFFSET(2);
    uint8_t *expected_src1 = expected_state + VREG_OFFSET(3);
    uint8_t *expected = expected_state + VREG_OFFSET(1);
    for (size_t i = 0; i < ({vl} + 7) / 8; ++i) {{
        src2[i] = (uint8_t)(0x81u ^ i); src1[i] = (uint8_t)(0x24u + i);
        expected_src2[i] = src2[i]; expected_src1[i] = src1[i];
    }}
    for (size_t i = 0; i < {vl}; ++i) {{
        uint8_t bit = (uint8_t)(1u << (i % 8));
        if ((src2[i / 8] | src1[i / 8]) & bit) expected[i / 8] |= bit;
        else expected[i / 8] &= (uint8_t)~bit;
    }}
{_call_or_benchmark("translated_func();", "vmor_mm")}
    return check_state();
}}
'''


def _vmor_alias_source() -> str:
    """vmor.mm 的 vd==vs2 别名，验证输入先读完再提交输出。"""
    vl = 173
    return _C_HEADER + f'''
extern void translated_func(void);
int main(void) {{
    init_state({vl});
    uint8_t *dst_src2 = simulated_cpu_state + VREG_OFFSET(1);
    uint8_t *src1 = simulated_cpu_state + VREG_OFFSET(2);
    uint8_t *expected_src1 = expected_state + VREG_OFFSET(2);
    uint8_t *expected = expected_state + VREG_OFFSET(1);
    for (size_t i = 0; i < ({vl} + 7) / 8; ++i) {{
        dst_src2[i] = (uint8_t)(0x81u ^ i);
        src1[i] = (uint8_t)(0x24u + i);
        expected[i] = dst_src2[i];
        expected_src1[i] = src1[i];
    }}
    for (size_t i = 0; i < {vl}; ++i) {{
        uint8_t bit = (uint8_t)(1u << (i % 8));
        if ((dst_src2[i / 8] | src1[i / 8]) & bit) expected[i / 8] |= bit;
        else expected[i / 8] &= (uint8_t)~bit;
    }}
{_call_or_benchmark("translated_func();", "vmor_mm_alias")}
    return check_state();
}}
'''


def _mask_scan_source(opcode: str) -> str:
    vl = 173
    expected_result = "9" if opcode == "vfirst.m" else "3"
    bits = (9, 37, 172)
    return _C_HEADER + f'''
extern long translated_func(void);
int main(void) {{
    init_state({vl});
    uint8_t *mask = simulated_cpu_state + VREG_OFFSET(1);
    uint8_t *expected_mask = expected_state + VREG_OFFSET(1);
    memset(mask, 0, ({vl} + 7) / 8); memcpy(expected_mask, mask, ({vl} + 7) / 8);
    const size_t bits[] = {{{", ".join(str(bit) for bit in bits)}}};
    for (size_t i = 0; i < sizeof(bits) / sizeof(bits[0]); ++i) {{
        mask[bits[i] / 8] |= (uint8_t)(1u << (bits[i] % 8));
        expected_mask[bits[i] / 8] = mask[bits[i] / 8];
    }}
    long got = -99;
{_call_or_benchmark("got = translated_func();", opcode.replace('.', '_'))}
    if (got != {expected_result}) {{ fprintf(stderr, "{opcode} result=%ld\\n", got); return 1; }}
    return check_state();
}}
'''


def _vsseg4e64_source() -> str:
    vl = 13
    return _C_HEADER + f'''
extern void translated_func(uint64_t *);
int main(void) {{
    init_state({vl});
    uint64_t memory[{vl * 4 + 8}], expected_memory[{vl * 4 + 8}];
    memset(memory, 0x3C, sizeof(memory)); memcpy(expected_memory, memory, sizeof(memory));
    const int regs[4] = {{24, 26, 28, 30}};
    for (size_t field = 0; field < 4; ++field) {{
        uint64_t *src = (uint64_t *)(simulated_cpu_state + VREG_OFFSET(regs[field]));
        uint64_t *expected_src = (uint64_t *)(expected_state + VREG_OFFSET(regs[field]));
        for (size_t i = 0; i < {vl}; ++i) {{
            src[i] = (uint64_t)(field * 1000 + i * 17 + 5); expected_src[i] = src[i];
            expected_memory[i * 4 + field] = src[i];
        }}
    }}
{_call_or_benchmark("translated_func(memory);", "vsseg4e64")}
    if (check_state()) return 1;
    if (memcmp(memory, expected_memory, sizeof(memory)) != 0) return 1;
    return 0;
}}
'''


def _vfwmul_vf_source() -> str:
    vl = 61
    return _C_HEADER + f'''
extern void translated_func(_Float16);
int main(void) {{
    init_state({vl});
    _Float16 *src = (_Float16 *)(simulated_cpu_state + VREG_OFFSET(12));
    _Float16 *expected_src = (_Float16 *)(expected_state + VREG_OFFSET(12));
    float *expected = (float *)(expected_state + VREG_OFFSET(8));
    for (size_t i = 0; i < {vl}; ++i) {{
        src[i] = (_Float16)((int)(i % 13) - 6); expected_src[i] = src[i];
        expected[i] = (float)src[i] * 2.0f;
    }}
{_call_or_benchmark("translated_func((_Float16)2.0);", "vfwmul_vf_e16_m1")}
    return check_state();
}}
'''


CASES = {
    **_first_batch_cases(),
    "vadd_e8_m1": Case("vadd_e8_m1", "vadd.vv v8, v12, v16", "sew=8,lmul=1", _integer_vadd_source(8, 97, 8, 12, 16)),
    "vadd_e32_m8": Case("vadd_e32_m8", "vadd.vv v8, v16, v24", "sew=32,lmul=8", _integer_vadd_source(32, 193, 8, 16, 24)),
    "vfmacc_vf_e64_m8": Case("vfmacc_vf_e64_m8", "vfmacc.vf v8, fa0, v16", "sew=64,lmul=8", _float_source("vfmacc.vf", 64, 77, 8, None, 16)),
    "vfmacc_vv_e32_m4": Case("vfmacc_vv_e32_m4", "vfmacc.vv v8, v12, v16", "sew=32,lmul=4", _float_source("vfmacc.vv", 32, 111, 8, 12, 16)),
    "vfmul_vf_e32_m2": Case("vfmul_vf_e32_m2", "vfmul.vf v8, v16, fa0", "sew=32,lmul=2", _float_source("vfmul.vf", 32, 51, 8, None, 16)),
    "vfnmsac_vf_e64_m4": Case("vfnmsac_vf_e64_m4", "vfnmsac.vf v8, fa0, v16", "sew=64,lmul=4", _float_source("vfnmsac.vf", 64, 41, 8, None, 16)),
    "vle32_m8": Case("vle32_m8", "vle32.v v8, (a0)", "sew=32,lmul=8", _unit_memory_source(True, 32, 173, 8)),
    "vse32_m8": Case("vse32_m8", "vse32.v v8, (a0)", "sew=32,lmul=8", _unit_memory_source(False, 32, 173, 8)),
    "vlse64_negative": Case("vlse64_negative", "vlse64.v v8, (a0), a1", "sew=64,lmul=4", _strided_source(True, 64, 49, 8, -16)),
    "vsse32_positive": Case("vsse32_positive", "vsse32.v v8, (a0), a1", "sew=32,lmul=8", _strided_source(False, 32, 97, 8, 8)),
    "vmv4r": Case("vmv4r", "vmv4r.v v8, v16", "sew=32,lmul=1", _whole_move_source(4, 8, 16)),
    "vl4re32": Case("vl4re32", "vl4re32.v v8, (a0)", "sew=32,lmul=1", _whole_memory_source(True, 4, 8)),
    "vs8r": Case("vs8r", "vs8r.v v16, (a0)", "sew=32,lmul=1", _whole_memory_source(False, 8, 16)),
    "masked_vadd_e32_m8": Case(
        "masked_vadd_e32_m8", "vadd.vv v8, v16, v24, v0.t", "sew=32,lmul=8",
        _integer_vadd_source(32, 193, 8, 16, 24, masked=True),
    ),
    "masked_vfmacc_vf_e64_m8": Case(
        "masked_vfmacc_vf_e64_m8", "vfmacc.vf v8, fa0, v16, v0.t", "sew=64,lmul=8",
        _float_source("vfmacc.vf", 64, 77, 8, None, 16, masked=True),
    ),
    "masked_vfmacc_vv_e32_m4": Case(
        "masked_vfmacc_vv_e32_m4", "vfmacc.vv v8, v12, v16, v0.t", "sew=32,lmul=4",
        _float_source("vfmacc.vv", 32, 111, 8, 12, 16, masked=True),
    ),
    "masked_vfmul_vf_e32_m2": Case(
        "masked_vfmul_vf_e32_m2", "vfmul.vf v8, v16, fa0, v0.t", "sew=32,lmul=2",
        _float_source("vfmul.vf", 32, 51, 8, None, 16, masked=True),
    ),
    "masked_vfnmsac_vf_e64_m4": Case(
        "masked_vfnmsac_vf_e64_m4", "vfnmsac.vf v8, fa0, v16, v0.t", "sew=64,lmul=4",
        _float_source("vfnmsac.vf", 64, 41, 8, None, 16, masked=True),
    ),
    "masked_vle32_m8": Case(
        "masked_vle32_m8", "vle32.v v8, (a0), v0.t", "sew=32,lmul=8",
        _unit_memory_source(True, 32, 173, 8, masked=True),
    ),
    "masked_vse32_m8": Case(
        "masked_vse32_m8", "vse32.v v8, (a0), v0.t", "sew=32,lmul=8",
        _unit_memory_source(False, 32, 173, 8, masked=True),
    ),
    "masked_vlse64_negative": Case(
        "masked_vlse64_negative", "vlse64.v v8, (a0), a1, v0.t", "sew=64,lmul=4",
        _strided_source(True, 64, 49, 8, -16, masked=True),
    ),
    "masked_vsse32_positive": Case(
        "masked_vsse32_positive", "vsse32.v v8, (a0), a1, v0.t", "sew=32,lmul=8",
        _strided_source(False, 32, 97, 8, 8, masked=True),
    ),
    "masked_vadd_vi_e8_m2": Case(
        "masked_vadd_vi_e8_m2", "vadd.vi v8, v12, 3, v0.t", "sew=8,lmul=2,ta,mu",
        _vadd_vi_source(masked=True),
    ),
    # 以下 conservative profile 用例不会改变运行时 ABI；它们让外部 RVV256
    # 机器分别验证保守路径，而不是把默认宽 profile 的通过结果外推。
    "default_masked_vadd_vi_e8_m2": Case(
        "default_masked_vadd_vi_e8_m2", "vadd.vi v8, v12, 3, v0.t", "sew=8,lmul=2,ta,mu",
        _vadd_vi_source(masked=True), wide_lmul=False,
    ),
    "default_masked_vrsub_vi_e8_m1": Case(
        "default_masked_vrsub_vi_e8_m1", "vrsub.vi v8, v12, 3, v0.t", "sew=8,lmul=1,ta,mu",
        _vrsub_vi_source(masked=True), wide_lmul=False,
    ),
    "default_masked_vle32_m8": Case(
        "default_masked_vle32_m8", "vle32.v v8, (a0), v0.t", "sew=32,lmul=8",
        _unit_memory_source(True, 32, 173, 8, masked=True), wide_lmul=False,
    ),
    "default_masked_vsse32_positive": Case(
        "default_masked_vsse32_positive", "vsse32.v v8, (a0), a1, v0.t", "sew=32,lmul=8",
        _strided_source(False, 32, 97, 8, 8, masked=True), wide_lmul=False,
    ),
    "masked_vwmacc_vx_e16_m1": Case(
        "masked_vwmacc_vx_e16_m1", "vwmacc.vx v8, a0, v12, v0.t", "sew=16,lmul=1,ta,mu",
        _vwmacc_vx_source(masked=True),
    ),
    "vwadd_wv_e16_m1": Case(
        "vwadd_wv_e16_m1", "vwadd.wv v8, v12, v16", "sew=16,lmul=1",
        _vwadd_wv_source(),
    ),
    "masked_vwredsum_e16_m1": Case(
        "masked_vwredsum_e16_m1", "vwredsum.vs v8, v12, v16, v0.t", "sew=16,lmul=1,ta,mu",
        _vwredsum_source(masked=True),
    ),
    "vmseq_vi_e8_m1": Case(
        "vmseq_vi_e8_m1", "vmseq.vi v1, v4, -1", "sew=8,lmul=1",
        _vmseq_vi_source(),
    ),
    "default_vmseq_vi_e8_m1": Case(
        "default_vmseq_vi_e8_m1", "vmseq.vi v1, v4, -1", "sew=8,lmul=1",
        _vmseq_vi_source(), wide_lmul=False,
    ),
    "vmor_mm": Case(
        "vmor_mm", "vmor.mm v1, v2, v3", "sew=8,lmul=2",
        _vmor_source(),
    ),
    "default_vmor_mm_alias": Case(
        "default_vmor_mm_alias", "vmor.mm v1, v1, v2", "sew=8,lmul=2",
        _vmor_alias_source(), wide_lmul=False,
    ),
    "vfirst_m": Case(
        "vfirst_m", "vfirst.m a0, v1", "sew=8,lmul=2",
        _mask_scan_source("vfirst.m"),
    ),
    "default_vfirst_m": Case(
        "default_vfirst_m", "vfirst.m a0, v1", "sew=8,lmul=2",
        _mask_scan_source("vfirst.m"), wide_lmul=False,
    ),
    "vcpop_m": Case(
        "vcpop_m", "vcpop.m a0, v1", "sew=8,lmul=2",
        _mask_scan_source("vcpop.m"),
    ),
    "default_vcpop_m": Case(
        "default_vcpop_m", "vcpop.m a0, v1", "sew=8,lmul=2",
        _mask_scan_source("vcpop.m"), wide_lmul=False,
    ),
    "default_vl4re32": Case(
        "default_vl4re32", "vl4re32.v v8, (a0)", "sew=32,lmul=1",
        _whole_memory_source(True, 4, 8), wide_lmul=False,
    ),
    "vsseg4e64": Case(
        "vsseg4e64", "vsseg4e64.v v24, (a0)", "sew=64,lmul=2",
        _vsseg4e64_source(),
    ),
    "vfwmul_vf_e16_m1": Case(
        "vfwmul_vf_e16_m1", "vfwmul.vf v8, v12, fa0", "sew=16,lmul=1",
        _vfwmul_vf_source(), march="rv64gcv_zfh_zvfh",
    ),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=(
            "list", "check-env", "translate", "assemble", "build", "run", "full",
            "bench-build", "bench-run", "clean",
        ),
    )
    parser.add_argument("--case", dest="case_name", default="all")
    parser.add_argument("--cc", default="riscv64-unknown-linux-gnu-gcc")
    parser.add_argument("--objdump", default="riscv64-unknown-linux-gnu-objdump")
    parser.add_argument("--qemu", default="qemu-riscv64")
    parser.add_argument("--qemu-cpu", default="rv64,v=true,vlen=256,elen=64,vext_spec=v1.0")
    parser.add_argument("--llvm-mc", default="/opt/homebrew/opt/llvm/bin/llvm-mc")
    parser.add_argument("--llvm-objdump", default="/opt/homebrew/opt/llvm/bin/llvm-objdump")
    parser.add_argument("--iterations", type=int, default=100000)
    return parser.parse_args()


def selected_cases(name: str) -> list[Case]:
    if name == "all":
        return [CASES[key] for key in sorted(CASES)]
    if name not in CASES:
        raise SystemExit(f"未知 case: {name}")
    return [CASES[name]]


def run(cmd: list[str], cwd: Path, stdout=None) -> None:
    subprocess.run(cmd, cwd=cwd, check=True, stdout=stdout)


def translate_case(case: Case) -> None:
    case.directory.mkdir(parents=True, exist_ok=True)
    instructions = AsmParser().parse_string(case.command)
    assembly = translate(
        instructions,
        init_vtype=case.vtype,
        func_name="translated_func",
        tls_state=False,
        wide_lmul=case.wide_lmul,
    )
    optimized_marker = (
        "RVV256-WIDE" in assembly
        or "RVV256-NATIVE-MASK" in assembly
        or "RVV256-NATIVE-WHOLE" in assembly
        or "Direct byte-aligned mask chunk into v0" in assembly
        or (case.name == "vsseg4e64" and "vsseg4e64.v" in assembly)
    )
    if not optimized_marker:
        profile = "默认宽 profile" if case.wide_lmul else "--conservative"
        raise SystemExit(f"case {case.name} 未进入预期 {profile} 优化路径")
    (case.directory / "translated.s").write_text(assembly, encoding="utf-8")
    (case.directory / "main.c").write_text(case.c_source, encoding="utf-8")
    print(f"[translate] {case.name}")


def build_case(case: Case, cc: str, objdump: str) -> None:
    run([cc, "-O2", f"-march={case.march}", "-mabi=lp64d", "-c", "translated.s", "-o", "translated.o"], case.directory)
    with (case.directory / "translated.objdump").open("w", encoding="utf-8") as output:
        run([objdump, "-dr", "translated.o"], case.directory, stdout=output)
    run([
        cc, "-O2", "-static", f"-march={case.march}", "-mabi=lp64d",
        "main.c", "translated.o", "-o", "verify.elf",
    ], case.directory)
    print(f"[build] {case.name}")


def assemble_case(case: Case, llvm_mc: str, llvm_objdump: str) -> None:
    """只依赖 LLVM RISC-V 后端，生成目标对象和可审计反汇编。"""
    run([
        llvm_mc,
        "-triple=riscv64-unknown-linux-gnu",
        "-mattr=+m,+a,+f,+d,+c,+v,+zfh,+zvfh,+zvfhmin",
        "-filetype=obj",
        "translated.s",
        "-o",
        "translated.o",
    ], case.directory)
    with (case.directory / "translated.objdump").open("w", encoding="utf-8") as output:
        run([llvm_objdump, "-dr", "--mattr=+v", "translated.o"], case.directory, stdout=output)
    print(f"[assemble] {case.name}")


def prepare_benchmark_case(case: Case) -> None:
    """生成同一输入的 legacy/wide 两份汇编和共享 benchmark C。"""
    case.directory.mkdir(parents=True, exist_ok=True)
    instructions = AsmParser().parse_string(case.command)
    for mode, wide_lmul in (("legacy", False), ("wide", True)):
        assembly = translate(
            instructions,
            init_vtype=case.vtype,
            func_name="translated_func",
            tls_state=False,
            wide_lmul=wide_lmul,
        )
        (case.directory / f"{mode}.s").write_text(assembly, encoding="utf-8")
    (case.directory / "benchmark.c").write_text(case.c_source, encoding="utf-8")


def build_benchmark_case(case: Case, cc: str, iterations: int) -> None:
    if iterations <= 0:
        raise SystemExit("--iterations 必须为正整数")
    prepare_benchmark_case(case)
    for mode in ("legacy", "wide"):
        run([
            cc, "-O2", "-static", f"-march={case.march}", "-mabi=lp64d",
            f"-DBENCHMARK_ITERATIONS={iterations}",
            "benchmark.c", f"{mode}.s", "-o", f"{mode}.elf",
        ], case.directory)
    print(f"[bench-build] {case.name}")


def run_benchmark_case(case: Case) -> None:
    """仅供真实 RVV256 目标机原生执行；不要用 QEMU 数据作性能结论。"""
    for mode in ("legacy", "wide"):
        print(f"[bench-run] {case.name} {mode}")
        run([f"./{mode}.elf"], case.directory)


def run_case(case: Case, qemu: str, qemu_cpu: str) -> None:
    run([qemu, "-cpu", qemu_cpu, "./verify.elf"], case.directory)
    print(f"[run] {case.name}: PASS")


def clean_case(case: Case) -> None:
    if case.directory.exists():
        shutil.rmtree(case.directory)


def main() -> int:
    args = parse_args()
    cases = selected_cases(args.case_name)
    if args.action == "list":
        for case in cases:
            profile = "默认宽 profile" if case.wide_lmul else "--conservative"
            print(f"{case.name}: {case.command} [{case.vtype}; {profile}]")
        return 0
    if args.action == "check-env":
        missing = [tool for tool in (args.cc, args.objdump, args.qemu) if shutil.which(tool) is None]
        if missing:
            print("缺少目标验证工具：")
            for tool in missing:
                print(f"  - {tool}")
            return 1
        print("RVV256 构建/运行工具可用。")
        return 0
    for case in cases:
        if args.action == "clean":
            clean_case(case)
            continue
        if args.action == "bench-build":
            build_benchmark_case(case, args.cc, args.iterations)
            continue
        if args.action == "bench-run":
            run_benchmark_case(case)
            continue
        if args.action in ("translate", "assemble", "full"):
            translate_case(case)
        if args.action == "assemble":
            assemble_case(case, args.llvm_mc, args.llvm_objdump)
        if args.action in ("build", "full"):
            build_case(case, args.cc, args.objdump)
        if args.action in ("run", "full"):
            run_case(case, args.qemu, args.qemu_cpu)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
