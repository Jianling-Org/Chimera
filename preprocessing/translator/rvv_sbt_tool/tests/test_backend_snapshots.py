"""后端能力和代表性汇编的轻量回归快照。

完整程序输出只在临时目录做 diff；仓库内快照保存排序 opcode 集合和规范化
汇编的摘要/行数，既能阻止能力静默漂移，也不会重新引入大型 golden 文件。
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from riscv.extensions.rvv.backends.rvv1024_transition.backend import RVV1024Dispatcher
from riscv.extensions.rvv.backends.rvv256.backend import RVV256Dispatcher
from riscv.extensions.rvv.backends.scalar.backend import ScalarDispatcher
from riscv.frontend.parser import AsmParser
import rvv_sbt
import rvv_sbt_rvv
import rvv_sbt_rvv1024


SNAPSHOT_PATH = Path(__file__).parent / "fixtures" / "backend_snapshots.json"


def _snapshot() -> dict:
    return json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))


def _digest_lines(lines: list[str]) -> str:
    payload = ("\n".join(lines) + "\n").encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _registry_snapshot(registry) -> dict[str, int | str]:
    opcodes = sorted(spec.opcode for spec in registry)
    return {
        "count": len(opcodes),
        "sha256": _digest_lines(opcodes),
    }


def _assembly_snapshot(assembly: str) -> dict[str, int | str]:
    # 只消除排版层空白；指令、操作数、标签、注释和顺序仍全部参与摘要。
    lines = [
        " ".join(line.split())
        for line in assembly.splitlines()
        if line.strip()
    ]
    return {
        "line_count": len(lines),
        "sha256": _digest_lines(lines),
    }


def test_registered_opcode_snapshots_are_stable():
    expected = _snapshot()["registries"]
    actual = {
        "scalar": _registry_snapshot(ScalarDispatcher().registry),
        "rvv256-wide": _registry_snapshot(RVV256Dispatcher(True).registry),
        "rvv256-conservative": _registry_snapshot(
            RVV256Dispatcher(False).registry
        ),
        "rvv1024-transition": _registry_snapshot(RVV1024Dispatcher().registry),
    }
    assert actual == expected


def test_representative_normalized_assembly_snapshots_are_stable():
    instructions = AsmParser().parse_string("vadd.vv v8, v16, v24")
    expected = _snapshot()["normalized_assembly"]
    actual = {
        "scalar-e32m1": _assembly_snapshot(
            rvv_sbt.translate(
                instructions, init_vtype="sew=32,lmul=1", raw=True
            )
        ),
        "rvv256-wide-e32m1": _assembly_snapshot(
            rvv_sbt_rvv.translate(
                instructions,
                init_vtype="sew=32,lmul=1",
                raw=True,
                wide_lmul=True,
            )
        ),
        "rvv256-conservative-e32m1": _assembly_snapshot(
            rvv_sbt_rvv.translate(
                instructions,
                init_vtype="sew=32,lmul=1",
                raw=True,
                wide_lmul=False,
            )
        ),
        "rvv1024-transition-e32m1": _assembly_snapshot(
            rvv_sbt_rvv1024.translate(
                instructions, init_vtype="sew=32,lmul=1", raw=True
            )
        ),
    }
    assert actual == expected
