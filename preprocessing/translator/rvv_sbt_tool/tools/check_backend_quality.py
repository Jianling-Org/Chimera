#!/usr/bin/env python3
"""检查 RVV256/RVV1024 后端不可接受的工程质量回归。"""

from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOTS = (ROOT / "src/riscv/extensions/rvv/backends" / "rvv256", ROOT / "src/riscv/extensions/rvv/backends" / "rvv1024_transition")
TRANSITION_HANDLERS = ROOT / "src/riscv/extensions/rvv/backends" / "rvv1024_transition" / "handlers"

# 翻译方向几何的权威是 riscv.extensions.rvv.runtime.geometry / riscv.extensions.rvv.analysis.model；后端内联这些
# 字面量会让两个 profile 对同一事实产生漂移。豁免行必须显式登记原因。
_FORBIDDEN_GEOMETRY_LITERALS = (
    "0.125, 0.25, 0.5, 1.0, 2.0, 4.0, 8.0",  # LEGAL_LMULS
    "0.125: \"mf8\"",                        # LMUL_TOKENS 起始行
    '"mf8": 0.125',                          # 反向 token 表
    '"CHIMERA_STATE_BASE"',                  # STATE_BASE_MARKER
    "256 // sew",                            # 目标块元素数（geometry.elements_per_chunk）
)


def python_files(root: Path):
    return tuple(sorted(root.rglob("*.py")))


def _deferred_backend_imports(tree: ast.AST, relative_name: str) -> list[str]:
    """报告函数/方法体内对 ``backends.*`` 的延迟 import。

    后端内部出现循环依赖时应抽出中立模块（如 ``lowering_metadata``、
    ``riscv.extensions.rvv.translation.specs``），而不是用函数内 import 掩盖。
    """

    violations: list[str] = []

    def visit(node: ast.AST, inside_function: bool) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for child in ast.iter_child_nodes(node):
                visit(child, True)
            return
        if inside_function and isinstance(node, (ast.Import, ast.ImportFrom)):
            if isinstance(node, ast.ImportFrom):
                candidates = [node.module or ""]
            else:
                candidates = [alias.name for alias in node.names]
            if any(name == "riscv.extensions.rvv.backends" or name.startswith("riscv.extensions.rvv.backends.") for name in candidates):
                violations.append(
                    f"{relative_name}:{node.lineno}: 函数内延迟 import backends 命名空间"
                    "（应抽出中立模块消除环，而非延迟绑定）"
                )
        for child in ast.iter_child_nodes(node):
            visit(child, inside_function)

    visit(tree, False)
    return violations


def main() -> int:
    violations: list[str] = []
    for root in BACKEND_ROOTS:
        for path in python_files(root):
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.ExceptHandler) and node.type is None:
                    violations.append(f"{path.relative_to(ROOT)}:{node.lineno}: bare except")
                if isinstance(node, ast.ExceptHandler) and isinstance(node.type, ast.Name) and node.type.id == "Exception":
                    violations.append(f"{path.relative_to(ROOT)}:{node.lineno}: broad except Exception")
            violations.extend(_deferred_backend_imports(tree, path.relative_to(ROOT)))
            if "cast(" in source:
                violations.append(f"{path.relative_to(ROOT)}: runtime cast() in backend")
            for literal in _FORBIDDEN_GEOMETRY_LITERALS:
                if literal in source:
                    violations.append(
                        f"{path.relative_to(ROOT)}: inline geometry/LMUL literal "
                        f"{literal!r}; 请消费 riscv.extensions.rvv.runtime.geometry / riscv.extensions.rvv.analysis.model"
                    )
    for path in python_files(TRANSITION_HANDLERS):
        source = path.read_text(encoding="utf-8")
        if "allocator.get_offset" in source or ".get_vreg_offset(" in source:
            violations.append(f"{path.relative_to(ROOT)}: bypasses RVV256StateView")
    if violations:
        print("\n".join(violations))
        return 1
    print("RVV256/RVV1024 backend quality checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
