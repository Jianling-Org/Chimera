"""三条公开 CLI 的片段、函数、程序与失败策略冒烟矩阵。"""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

import pytest


TOOL_ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable or "python3"
SUPPORTED_COMMAND = "vadd.vv v8, v16, v24"
MASKED_COMMAND = "vadd.vv v8, v16, v24, v0.t"
INIT_VTYPE = "sew=32,lmul=1"


def _run(script: str, *arguments: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run(
        [PYTHON, str(TOOL_ROOT / script), *arguments],
        cwd=TOOL_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


@pytest.mark.parametrize(
    ("script", "extra", "marker"),
    (
        ("rvv_sbt.py", (), "vadd.vv: v8 = v16 + v24"),
        ("rvv_sbt_rvv.py", (), "RVV256-WIDE: vadd.vv"),
        (
            "rvv_sbt_rvv.py",
            ("--conservative",),
            "vadd.vv v8, v16, v24 (256-bit mode)",
        ),
        (
            "rvv_sbt_rvv1024.py",
            (),
            "RVV256→RVV1024 迁移 profile guard: vadd.vv",
        ),
    ),
)
def test_supported_fragment_and_helper_mode_matrix(script, extra, marker):
    """默认/保守 profile 均通过 CLI，helper 基址模式仍保留旧 ABI。"""

    result = _run(
        script,
        "-c",
        SUPPORTED_COMMAND,
        "--init-vtype",
        INIT_VTYPE,
        "--raw",
        "--state-base-mode",
        "helper",
        *extra,
    )
    assert result.returncode == 0, result.stderr
    assert marker in result.stdout
    assert "call    get_simulated_cpu_state_addr@plt" in result.stdout


@pytest.mark.parametrize(
    ("script", "extra"),
    (
        ("rvv_sbt.py", ()),
        ("rvv_sbt_rvv.py", ()),
        ("rvv_sbt_rvv1024.py", ()),
    ),
)
def test_function_file_mode_matrix(tmp_path, script, extra):
    """不提供 lib_name 时，三条 CLI 都保持单函数文件入口。"""

    source = tmp_path / f"{script}.function.s"
    output = tmp_path / f"{script}.function.out.s"
    source.write_text(
        "foo:\n"
        "    vsetvli a5, a0, e32, m1, ta, ma\n"
        "    vadd.vv v8, v16, v24\n"
        "    ret\n",
        encoding="utf-8",
    )
    result = _run(script, str(source), "-o", str(output), *extra)
    assert result.returncode == 0, result.stderr
    generated = output.read_text(encoding="utf-8")
    assert "foo:" in generated
    assert "ret" in generated


@pytest.mark.parametrize(
    ("script", "extra", "state_symbol"),
    (
        ("rvv_sbt.py", (), "simulated_cpu_state_ptr"),
        (
            "rvv_sbt_rvv.py",
            ("--emit-jump-site-markers",),
            "simulated_cpu_state_riscv64_rvv_1024_riscv64_rvv_256",
        ),
        (
            "rvv_sbt_rvv1024.py",
            (),
            "simulated_cpu_state_riscv64_rvv_256_riscv64_rvv_1024",
        ),
    ),
)
def test_program_mode_matrix(tmp_path, script, extra, state_symbol):
    """程序模式保留函数/原偏移标签，并验证三后端各自的状态符号。"""

    source = tmp_path / f"{script}.objdump.s"
    output = tmp_path / f"{script}.program.out.s"
    source.write_text(
        "0000000000001000 <foo>:\n"
        "    1000: 0d0577d7             vsetvli a5, a0, e32, m1, ta, ma\n"
        "    1004: 02050457             vadd.vv v8, v16, v24\n"
        "    1008: 8082                 ret\n",
        encoding="utf-8",
    )
    result = _run(script, str(source), "smoke", "-o", str(output), *extra)
    assert result.returncode == 0, result.stderr
    generated = output.read_text(encoding="utf-8")
    assert "foo_translated:" in generated
    assert "branch_j_target_1004:" in generated
    assert "# 原偏移: 0x1004" in generated
    assert state_symbol in generated


def test_cli_failure_policy_and_mask_matrix(tmp_path):
    """同一未支持输入分别触发标量失败和两条 RVV 路径的 ebreak。"""

    scalar = _run(
        "rvv_sbt.py",
        "-c",
        "vunknown.vv v1, v2, v3",
        "--init-vtype",
        INIT_VTYPE,
        "--raw",
    )
    assert scalar.returncode != 0
    assert "Unsupported instruction" in scalar.stderr

    rvv256 = _run(
        "rvv_sbt_rvv.py",
        "-c",
        "vunknown.vv v1, v2, v3",
        "--init-vtype",
        INIT_VTYPE,
        "--raw",
    )
    assert rvv256.returncode == 0, rvv256.stderr
    assert "RVV256 fallback" in rvv256.stdout
    assert "ebreak" in rvv256.stdout

    existing = tmp_path / "transition-existing.s"
    existing.write_text("用户已有内容\n", encoding="utf-8")
    transition = _run(
        "rvv_sbt_rvv1024.py",
        "-c",
        "vdiv.vv v8, v16, v24, v0.t",
        "--init-vtype",
        INIT_VTYPE,
        "--raw",
        "-o",
        str(existing),
    )
    assert transition.returncode == 0, transition.stderr
    generated = existing.read_text(encoding="utf-8")
    assert "用户已有内容" not in generated
    assert "RVV1024 fallback" in generated
    assert "    ebreak" in generated


def test_transition_cli_falls_back_for_unknown_vtype(tmp_path):
    output = tmp_path / "unknown-vtype.s"
    result = _run(
        "rvv_sbt_rvv1024.py",
        "-c",
        SUPPORTED_COMMAND,
        "--raw",
        "-o",
        str(output),
    )
    assert result.returncode == 0, result.stderr
    generated = output.read_text(encoding="utf-8")
    assert "RVV1024 fallback" in generated
    assert "source vtype analysis contains only unknown entries" in generated
    assert "    ebreak" in generated


@pytest.mark.parametrize(
    ("script", "marker"),
    (
        ("rvv_sbt.py", "# masked form:"),
        ("rvv_sbt_rvv.py", "v0.t"),
        ("rvv_sbt_rvv1024.py", "载入源 v0.t 执行掩码"),
    ),
)
def test_supported_masked_cli_forms_are_not_silently_unmasked(script, marker):
    result = _run(
        script,
        "-c",
        MASKED_COMMAND,
        "--init-vtype",
        INIT_VTYPE,
        "--raw",
    )
    assert result.returncode == 0, result.stderr
    assert marker in result.stdout
    if script == "rvv_sbt_rvv1024.py":
        # 过渡后端每个入口的 profile/vstart 动态门禁自带拒绝分支；这不是
        # 未支持指令 fallback，支持 form 的 native 指令仍必须存在。
        assert "profile 或 vstart 不满足迁移前提" in result.stdout
        assert "Unsupported RVV instruction" not in result.stdout
    else:
        assert "fallback" not in result.stdout
        assert all("unsupported nonzero source vstart" in line
                   for line in result.stdout.splitlines() if "ebreak" in line)
