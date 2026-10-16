"""RVV256→RVV1024 独立目标差分 runner 的本地回归。

这里仅测试 case 定义、helper ABI 生成和 LLVM 静态汇编。真实 C
reference/candidate 的完整状态差分必须在 VLEN=1024 RISC-V 环境执行。
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from verify.rvv1024_transition import run_verify


def test_minimal_transition_cases_cover_required_dataflows():
    """runner 至少覆盖 CSR、算术、掩码/扫描和双向 unit memory。"""
    assert set(run_verify.CASES) == {
        "csrwi_vxrm",
        "vadd_e32_m1",
        "masked_vadd_e32_m1",
        "vmseq_vfirst_e8_m1",
        "vle32_e32_m1",
        "vse32_e32_m1",
    }
    assert "v0.t" in run_verify.CASES["masked_vadd_e32_m1"].command
    assert "vmseq.vi" in run_verify.CASES["vmseq_vfirst_e8_m1"].command
    assert "vfirst.m" in run_verify.CASES["vmseq_vfirst_e8_m1"].command
    assert "csrwi vxrm, 1" == run_verify.CASES["csrwi_vxrm"].command
    assert "store_u64(expected_state, VCSR_OFFSET, 3)" in run_verify.CASES["csrwi_vxrm"].c_source


@pytest.mark.parametrize("case_name", sorted(run_verify.CASES))
def test_translate_case_uses_helper_and_compact_state_harness(
    case_name: str, tmp_path: Path
):
    """生成物必须绑定 helper state-base，而 C reference 明确比较完整 state。"""
    directory = run_verify.translate_case(run_verify.CASES[case_name], tmp_path)
    assembly = (directory / "translated.s").read_text(encoding="utf-8")
    harness = (directory / "main.c").read_text(encoding="utf-8")

    assert "get_simulated_cpu_state_addr@plt" in assembly
    assert "CHIMERA_STATE_BASE" in assembly
    assert "#define STATE_SIZE 0x1040u" in harness
    assert "#define RAW_VREG_OFFSET(n) ((size_t)(n) * 32u)" in harness
    assert "hardware_vlenb != 128" in harness
    assert "state.vlenb 不是 RVV256 所需的 32" in harness
    assert "state canary mismatch" in harness


def test_memory_harnesses_compare_payload_and_canaries():
    """load/store case 不能只比较 vector state，还要比较相关内存及双侧 canary。"""
    for name in ("vle32_e32_m1", "vse32_e32_m1"):
        harness = run_verify.CASES[name].c_source
        assert "memory canary mismatch" in harness
        assert "memory payload mismatch" in harness
        assert "check_u32_memory" in harness


def test_representative_candidate_is_accepted_by_llvm_mc(tmp_path: Path):
    """这只是目标汇编语法门禁，不替代 VLEN=1024 的运行时语义差分。"""
    llvm_mc = shutil.which("llvm-mc")
    if llvm_mc is None:
        homebrew = Path("/opt/homebrew/opt/llvm/bin/llvm-mc")
        llvm_mc = str(homebrew) if homebrew.exists() else None
    if llvm_mc is None:
        pytest.skip("未找到带 RISC-V target 的 llvm-mc")

    run_verify.assemble_case(
        run_verify.CASES["masked_vadd_e32_m1"],
        tmp_path,
        llvm_mc,
        run_verify._default_llvm_tool("llvm-objdump"),
    )
    assert (tmp_path / "masked_vadd_e32_m1" / "translated.o").exists()
