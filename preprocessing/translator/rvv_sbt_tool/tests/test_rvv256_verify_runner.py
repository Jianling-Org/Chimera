"""目标 RVV256 语义 runner 的 case 完整性测试。"""

import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


RUNNER_PATH = (
    Path(__file__).resolve().parents[1]
    / "verify"
    / "rvv256_wide"
    / "run_verify.py"
)
REPORT_PATH = RUNNER_PATH.with_name("report_codegen.py")


def _load_runner():
    spec = importlib.util.spec_from_file_location("rvv256_wide_verify_runner", RUNNER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_report():
    spec = importlib.util.spec_from_file_location("rvv256_wide_codegen_report", REPORT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_target_verify_cases_cover_optimized_families_and_generate_assembly():
    runner = _load_runner()
    from riscv.extensions.rvv.runtime.contract import RVV1024_TO_RVV256
    required = {
        "vadd_e8_m1",
        "vadd_e32_m8",
        "vfmacc_vf_e64_m8",
        "vfmacc_vv_e32_m4",
        "vfmul_vf_e32_m2",
        "vfnmsac_vf_e64_m4",
        "vle32_m8",
        "vse32_m8",
        "vlse64_negative",
        "vsse32_positive",
        "vmv4r",
        "vl4re32",
        "vs8r",
        "masked_vadd_e32_m8",
        "masked_vfmacc_vf_e64_m8",
        "masked_vfmacc_vv_e32_m4",
        "masked_vfmul_vf_e32_m2",
        "masked_vfnmsac_vf_e64_m4",
        "masked_vle32_m8",
        "masked_vse32_m8",
        "masked_vlse64_negative",
        "masked_vsse32_positive",
        "masked_vadd_vi_e8_m2",
        "masked_vwmacc_vx_e16_m1",
        "vwadd_wv_e16_m1",
        "masked_vwredsum_e16_m1",
        "vmseq_vi_e8_m1",
        "vmor_mm",
        "vfirst_m",
        "vcpop_m",
        "vsseg4e64",
        "vfwmul_vf_e16_m1",
        "default_masked_vadd_vi_e8_m2",
        "default_masked_vrsub_vi_e8_m1",
        "default_masked_vle32_m8",
        "default_masked_vsse32_positive",
        "default_vmseq_vi_e8_m1",
        "default_vmor_mm_alias",
        "default_vfirst_m",
        "default_vcpop_m",
        "default_vl4re32",
        "wide_vdiv_vx_divzero_e32_m8",
        "wide_vdiv_vx_min_negative_e64_m4",
    }
    assert required <= set(runner.CASES)

    for case in runner.CASES.values():
        instructions = runner.AsmParser().parse_string(case.command)
        assembly = runner.translate(
            instructions,
            init_vtype=case.vtype,
            func_name="translated_func",
            tls_state=False,
            wide_lmul=case.wide_lmul,
        )
        assert (
            "RVV256-WIDE" in assembly
            or "RVV256-NATIVE-MASK" in assembly
            or "RVV256-NATIVE-WHOLE" in assembly
            or "Direct byte-aligned mask chunk into v0" in assembly
            or (case.name == "vsseg4e64" and "vsseg4e64.v" in assembly)
        ), case.name
        assert f"la      t6, {RVV1024_TO_RVV256.state_symbol}" in assembly
        assert "simulated_cpu_state_ptr" not in assembly
        assert "check_state" in case.c_source
        assert "STATE_SIZE 0x1040" in case.c_source
        assert "CANARY_SIZE 64" in case.c_source
        assert "state canary mismatch" in case.c_source
        assert "BENCHMARK_ITERATIONS" in case.c_source
        assert "rdcycle" in case.c_source
        if "masked_" in case.name:
            assert "init_mask" in case.c_source
            assert "mask_enabled" in case.c_source


def test_vdiv_edge_cases_keep_rvv_special_results_explicit():
    """除零和最小负数/-1 不得退化为 C 未定义有符号除法。"""
    runner = _load_runner()
    divzero = runner.CASES["wide_vdiv_vx_divzero_e32_m8"]
    min_negative = runner.CASES["wide_vdiv_vx_min_negative_e64_m4"]
    assert "scalar_value = (int32_t)0" in divzero.c_source
    assert "scalar_value = (int64_t)-1" in min_negative.c_source
    assert "chimera_ref_sdiv" in divzero.c_source
    assert "chimera_ref_sdiv" in min_negative.c_source


def test_all_target_reference_sources_pass_host_c_syntax_check(tmp_path):
    """本机只检查 C reference 语法；不把它表述为目标机器语义执行。"""
    cc = shutil.which("cc")
    if cc is None:
        pytest.skip("缺少 host C compiler")
    runner = _load_runner()
    for case in runner.CASES.values():
        source = tmp_path / f"{case.name}.c"
        source.write_text(case.c_source, encoding="utf-8")
        subprocess.run(
            [cc, "-std=c11", "-fsyntax-only", str(source)],
            check=True,
            capture_output=True,
            text=True,
        )


def test_program_report_distinguishes_large_input_role_from_vector_coverage():
    """通用全程序入口必须显式报告 RVV 数量，避免把大文件等同于向量覆盖。"""
    report_module = _load_report()
    fixture = Path(__file__).parent / "fixtures" / "objdump" / "vadd_rvv.objdump.s"
    report = report_module.collect_program_report(
        fixture,
        lib_name="vadd_fixture",
    )
    assert report["function_count"] > 0
    assert report["instruction_count"] > 0
    assert report["vector_instruction_count"] > 0
    assert report["masked_vector_instruction_count"] == 0
    assert report["legacy_wide_identical"] is False
    assert report["wide"]["wide_blocks"] > 0


def test_codegen_report_keeps_whole_register_compatibility_metric_nonzero():
    """新 native marker 不能让旧 wide_whole_blocks 消费方误判为零优化。"""
    report_module = _load_report()
    metrics = report_module.assembly_metrics(
        "# RVV256-NATIVE-WHOLE: vmv1r.v, 128 bytes, state ABI fixed-slot copy\n"
        "# RVV256-NATIVE-WHOLE-MEM: vl1r.v, 128 bytes, state ABI fixed-slot transfer\n"
    )
    assert metrics["native_whole_blocks"] == 2
    assert metrics["wide_whole_blocks"] == 2


def _llvm_mc_path() -> str | None:
    discovered = shutil.which("llvm-mc")
    if discovered:
        return discovered
    homebrew = Path("/opt/homebrew/opt/llvm/bin/llvm-mc")
    return str(homebrew) if homebrew.exists() else None


@pytest.mark.skipif(_llvm_mc_path() is None, reason="缺少带 RISC-V 后端的 llvm-mc")
def test_all_target_verify_cases_assemble_as_rv64gcv(tmp_path):
    """真实调用 LLVM RISC-V 汇编器，防止只通过字符串测试的非法操作数。"""
    runner = _load_runner()
    llvm_mc = _llvm_mc_path()
    assert llvm_mc is not None
    for case in runner.CASES.values():
        instructions = runner.AsmParser().parse_string(case.command)
        assembly = runner.translate(
            instructions,
            init_vtype=case.vtype,
            func_name="translated_func",
            tls_state=False,
            wide_lmul=case.wide_lmul,
        )
        source = tmp_path / f"{case.name}.s"
        obj = tmp_path / f"{case.name}.o"
        source.write_text(assembly, encoding="utf-8")
        subprocess.run(
            [
                llvm_mc,
                "-triple=riscv64-unknown-linux-gnu",
                "-mattr=+m,+a,+f,+d,+c,+v,+zfh,+zvfh,+zvfhmin",
                "-filetype=obj",
                str(source),
                "-o",
                str(obj),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        assert obj.stat().st_size > 0
