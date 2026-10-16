#!/usr/bin/env python3
"""Validate and summarize one clean Chimera gate-census build."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import TextIO


MECHANISMS = ("LV", "SLP", "MEMOP", "MERGE")
LABELS = {
    "LV": "Loop Vectorizer",
    "SLP": "SLP Vectorizer",
    "MEMOP": "MemOp 向量展开",
    "MERGE": "Store Merge",
    "TOTAL": "全部机制并集",
}


def canonical_name(name: str) -> str:
    """Map Itanium base/complete constructor and destructor aliases together."""
    return (
        # C1/C2 and D1/D2 are discriminator tags in an Itanium mangled
        # constructor/destructor name.  The suffix is not necessarily ``E``
        # (a constructor may have parameters), so normalize the tag itself.
        name.replace("C1", "C2")
        .replace("D1", "D2")
    )


def _read_gate_names(path: Path) -> set[str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ValueError(f"无法读取 gate 清单 {path}: {exc}") from exc
    return {canonical_name(line.strip()) for line in lines if line.strip()}


def _read_census(path: Path) -> dict[str, dict[str, set[str]]]:
    events = {
        mechanism: {"formed": set(), "blocked": set()}
        for mechanism in MECHANISMS
    }
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ValueError(f"无法读取 census {path}: {exc}") from exc

    for line_number, raw in enumerate(lines, 1):
        if not raw.strip():
            continue
        fields = raw.split("\t")
        if len(fields) != 4 or fields[0] != "implicit-vector-census":
            raise ValueError(f"{path}:{line_number}: 非法 census 行: {raw!r}")
        _, mechanism, name, action = fields
        if mechanism not in MECHANISMS:
            raise ValueError(f"{path}:{line_number}: 未知机制 {mechanism!r}")
        if action not in ("formed", "blocked"):
            raise ValueError(f"{path}:{line_number}: 未知动作 {action!r}")
        name = canonical_name(name.strip())
        if not name:
            raise ValueError(f"{path}:{line_number}: 函数名为空")
        events[mechanism][action].add(name)
    return events


def build_rows(census_path: Path, gate_path: Path) -> dict[str, tuple[int, int, int]]:
    gate_names = _read_gate_names(gate_path)
    events = _read_census(census_path)
    rows: dict[str, tuple[int, int, int]] = {}
    all_eligible: set[str] = set()
    all_blocked: set[str] = set()
    all_formed: set[str] = set()

    for mechanism in MECHANISMS:
        formed = events[mechanism]["formed"]
        blocked = events[mechanism]["blocked"]
        conflict = formed & blocked
        if conflict:
            names = ", ".join(sorted(conflict))
            raise ValueError(f"{mechanism}: 同一函数同时 formed/blocked: {names}")
        outside_gate = blocked - gate_names
        if outside_gate:
            names = ", ".join(sorted(outside_gate))
            raise ValueError(f"{mechanism}: blocked 不属于 gate 清单: {names}")
        eligible = formed | blocked
        rows[mechanism] = (len(eligible), len(blocked), len(formed))
        all_eligible.update(eligible)
        all_blocked.update(blocked)
        all_formed.update(formed)

    global_conflict = all_formed & all_blocked
    if global_conflict:
        names = ", ".join(sorted(global_conflict))
        raise ValueError(f"跨机制同一函数同时 formed/blocked: {names}")

    rows["TOTAL"] = (
        len(all_eligible),
        len(all_blocked),
        len(all_eligible - all_blocked),
    )
    return rows


def _rate(eligible: int, blocked: int) -> str:
    return "-" if eligible == 0 else f"{blocked / eligible * 100:.2f}%"


def print_report(rows: dict[str, tuple[int, int, int]], output: TextIO = sys.stdout) -> None:
    print("| 机制 | 可隐式生成函数数 | 被 gate 阻止函数数 | 保留隐式生成函数数 | 阻止率 |", file=output)
    print("|---|---:|---:|---:|---:|", file=output)
    for mechanism in (*MECHANISMS, "TOTAL"):
        eligible, blocked, retained = rows[mechanism]
        print(
            f"| {LABELS[mechanism]} | {eligible} | {blocked} | {retained} | "
            f"{_rate(eligible, blocked)} |",
            file=output,
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--census", required=True, type=Path)
    parser.add_argument("--gate-list", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        rows = build_rows(args.census, args.gate_list)
    except ValueError as exc:
        parser.error(str(exc))
    print_report(rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
