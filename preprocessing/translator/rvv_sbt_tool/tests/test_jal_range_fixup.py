"""翻译器内部对象级本地跳转范围修正测试。"""

from __future__ import annotations

from pathlib import Path

import pytest

import riscv.codegen.jal_range_fixup as jal_range_fixup


def _mock_readelf(monkeypatch, *, symbols: str, relocations: str) -> None:
    """用固定 readelf 文本测试解析逻辑，不要求本机安装 RISC-V 工具链。"""

    def fake_run(command):
        if "-sW" in command:
            return iter(symbols.splitlines())
        if "-rW" in command:
            return iter(relocations.splitlines())
        raise AssertionError(command)

    monkeypatch.setattr(jal_range_fixup, "_run_lines", fake_run)


def test_inspect_object_maps_out_of_range_jal_to_source_site(monkeypatch):
    symbols = """
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     1: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT    1 chimera_j_site_1000
     2: 0000000000100000     0 NOTYPE  LOCAL  DEFAULT    1 branch_j_target_2000
"""
    relocations = """
Relocation section '.rela.text' at offset 0x0 contains 1 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
0000000000000000  0000000000000000 R_RISCV_JAL 0000000000100000 branch_j_target_2000 + 0
"""
    _mock_readelf(monkeypatch, symbols=symbols, relocations=relocations)

    report = jal_range_fixup.inspect_object(Path("probe.o"), readelf="readelf")

    assert report.out_of_range_sites == frozenset({0x1000})
    assert not report.unclassified_issues
    assert not report.branch_issues


def test_inspect_object_accepts_jal_and_rvc_jump_boundaries(monkeypatch):
    symbols = """
     1: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT    1 chimera_j_site_1000
     2: 00000000000ffffe     0 NOTYPE  LOCAL  DEFAULT    1 branch_j_target_2000
     3: 0000000000002000     0 NOTYPE  LOCAL  DEFAULT    1 chimera_j_site_3000
     4: 00000000000027fe     0 NOTYPE  LOCAL  DEFAULT    1 branch_j_target_3004
"""
    relocations = """
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
0000000000000000  0000000000000000 R_RISCV_JAL 00000000000ffffe branch_j_target_2000 + 0
0000000000002000  0000000000000000 R_RISCV_RVC_JUMP 00000000000027fe branch_j_target_3004 + 0
"""
    _mock_readelf(monkeypatch, symbols=symbols, relocations=relocations)

    report = jal_range_fixup.inspect_object(Path("probe.o"))

    assert not report.out_of_range_sites
    assert not report.unclassified_issues
    assert not report.branch_issues


def test_inspect_object_rejects_unclassified_jal_overflow(monkeypatch):
    symbols = """
     1: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT    1 unrelated_label
     2: 0000000000100000     0 NOTYPE  LOCAL  DEFAULT    1 branch_j_target_2000
"""
    relocations = """
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
0000000000000000  0000000000000000 R_RISCV_JAL 0000000000100000 branch_j_target_2000 + 0
"""
    _mock_readelf(monkeypatch, symbols=symbols, relocations=relocations)

    report = jal_range_fixup.inspect_object(Path("probe.o"))

    assert not report.out_of_range_sites
    assert len(report.unclassified_issues) == 1
    assert report.unclassified_issues[0].site is None


def test_inspect_object_rejects_undefined_direct_target(monkeypatch):
    """无法解析目标符号时不能静默跳过直接跳转重定位。"""

    symbols = """
     1: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT    1 chimera_j_site_1000
"""
    relocations = """
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
0000000000000000  0000000000000000 R_RISCV_JAL 0000000000000000 missing_target + 0
"""
    _mock_readelf(monkeypatch, symbols=symbols, relocations=relocations)

    report = jal_range_fixup.inspect_object(Path("probe.o"))

    assert not report.out_of_range_sites
    assert len(report.unclassified_issues) == 1
    assert report.unclassified_issues[0].target_value is None


def test_inspect_object_reports_branch_overflow_separately(monkeypatch):
    symbols = """
     1: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT    1 chimera_j_site_1000
     2: 0000000000002000     0 NOTYPE  LOCAL  DEFAULT    1 branch_j_target_2000
"""
    relocations = """
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
0000000000000000  0000000000000000 R_RISCV_BRANCH 0000000000002000 branch_j_target_2000 + 0
"""
    _mock_readelf(monkeypatch, symbols=symbols, relocations=relocations)

    report = jal_range_fixup.inspect_object(Path("probe.o"))

    assert not report.out_of_range_sites
    assert not report.unclassified_issues
    assert len(report.branch_issues) == 1


def test_resolve_jal_ranges_repeats_then_emits_clean_output(monkeypatch):
    """新发现的 site 进入下一轮，正式轮次关闭探测标签。"""

    translator_calls = []
    reports = iter(
        [
            jal_range_fixup.RelocationReport(
                out_of_range_sites=frozenset({0x1000}),
                unclassified_issues=(),
                branch_issues=(),
            ),
            jal_range_fixup.RelocationReport(
                out_of_range_sites=frozenset(),
                unclassified_issues=(),
                branch_issues=(),
            ),
            jal_range_fixup.RelocationReport(
                out_of_range_sites=frozenset(),
                unclassified_issues=(),
                branch_issues=(),
            ),
        ]
    )

    def fake_translate(sites, emit_markers):
        translator_calls.append((set(sites), emit_markers))
        return "translated"

    def fake_compile(**kwargs):
        kwargs["object_path"].write_bytes(b"object")

    monkeypatch.setattr(jal_range_fixup, "_compile_object", fake_compile)
    monkeypatch.setattr(
        jal_range_fixup,
        "inspect_object",
        lambda *args, **kwargs: next(reports),
    )

    output, sites = jal_range_fixup.resolve_jal_ranges(
        translate_round=fake_translate,
        compiler="gcc",
        max_iterations=3,
    )

    assert sites == frozenset({0x1000})
    assert translator_calls == [
        (set(), True),
        ({0x1000}, True),
        ({0x1000}, False),
    ]
    assert output == "translated"


def test_resolve_jal_ranges_rejects_out_of_scope_overflow(monkeypatch):
    """未映射直接跳转或条件分支越界不能被误判为修复成功。"""

    def fake_compile(**kwargs):
        kwargs["object_path"].write_bytes(b"object")

    monkeypatch.setattr(jal_range_fixup, "_compile_object", fake_compile)

    reports = [
        jal_range_fixup.RelocationReport(
            out_of_range_sites=frozenset(),
            unclassified_issues=(
                jal_range_fixup.RelocationIssue(
                    relocation_type="R_RISCV_JAL",
                    place=0,
                    target="branch_j_target_2000",
                    target_value=0x100000,
                    site=None,
                    delta=0x100000,
                ),
            ),
            branch_issues=(),
        ),
        jal_range_fixup.RelocationReport(
            out_of_range_sites=frozenset(),
            unclassified_issues=(),
            branch_issues=(
                jal_range_fixup.RelocationIssue(
                    relocation_type="R_RISCV_BRANCH",
                    place=0,
                    target="branch_j_target_2000",
                    target_value=0x2000,
                    site=None,
                    delta=0x2000,
                ),
            ),
        ),
    ]

    for report, message in zip(
        reports,
        ("无法映射回 emitter 本地 j", "超范围 R_RISCV_BRANCH"),
    ):
        def fake_inspect(*args, report=report, **kwargs):
            return report

        monkeypatch.setattr(jal_range_fixup, "inspect_object", fake_inspect)
        with pytest.raises(jal_range_fixup.JalRangeFixupError, match=message):
            jal_range_fixup.resolve_jal_ranges(
                translate_round=lambda sites, emit_markers: "translated",
                compiler="gcc",
            )


def test_resolve_jal_ranges_reports_non_convergence(monkeypatch):
    """每轮持续发现新 site 时必须到达上限并失败。"""

    reports = iter(
        [
            jal_range_fixup.RelocationReport(
                out_of_range_sites=frozenset({0x1000}),
                unclassified_issues=(),
                branch_issues=(),
            ),
            jal_range_fixup.RelocationReport(
                out_of_range_sites=frozenset({0x1004}),
                unclassified_issues=(),
                branch_issues=(),
            ),
        ]
    )

    def fake_compile(**kwargs):
        kwargs["object_path"].write_bytes(b"object")

    monkeypatch.setattr(jal_range_fixup, "_compile_object", fake_compile)
    monkeypatch.setattr(
        jal_range_fixup,
        "inspect_object",
        lambda *args, **kwargs: next(reports),
    )

    with pytest.raises(jal_range_fixup.JalRangeFixupError, match="超过 2 轮"):
        jal_range_fixup.resolve_jal_ranges(
            translate_round=lambda sites, emit_markers: "translated",
            compiler="gcc",
            max_iterations=2,
        )


def test_resolve_jal_ranges_rejects_probe_marker_in_final_output(monkeypatch):
    """正式轮不能泄漏第一轮使用的源地址探测标签。"""

    def fake_compile(**kwargs):
        kwargs["object_path"].write_bytes(b"object")

    monkeypatch.setattr(jal_range_fixup, "_compile_object", fake_compile)
    monkeypatch.setattr(
        jal_range_fixup,
        "inspect_object",
        lambda *args, **kwargs: jal_range_fixup.RelocationReport(
            out_of_range_sites=frozenset(),
            unclassified_issues=(),
            branch_issues=(),
        ),
    )

    def fake_translate(sites, emit_markers):
        if emit_markers:
            return "probe"
        return "chimera_j_site_1000:\n    j branch_j_target_2000"

    with pytest.raises(jal_range_fixup.JalRangeFixupError, match="探测标签"):
        jal_range_fixup.resolve_jal_ranges(
            translate_round=fake_translate,
            compiler="gcc",
        )
