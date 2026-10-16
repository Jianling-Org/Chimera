#!/usr/bin/env python3
"""检查 RVV256/RVV1024 后端不可接受的工程质量回归。"""

from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOTS = (ROOT / "src/riscv/extensions/rvv/backends" / "rvv256", ROOT / "src/riscv/extensions/rvv/backends" / "rvv1024_transition")
TRANSITION_HANDLERS = ROOT / "src/riscv/extensions/rvv/backends" / "rvv1024_transition" / "handlers"

# Only the established geometry patterns are forbidden, not equal scalar values.
_LMUL_VALUES = {0.125, 0.25, 0.5, 1.0, 2.0, 4.0, 8.0}
_LMUL_COLLECTION_NAMES = {"LEGAL_LMULS", "SUPPORTED_LMUL", "SUPPORTED_LMULS"}


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


def _inline_geometry(node: ast.AST) -> str | None:
    if isinstance(node, (ast.Assign, ast.AnnAssign)):
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        value = node.value
        if isinstance(value, ast.Constant) and value.value == "CHIMERA_STATE_BASE":
            return "STATE_BASE_MARKER"
        if any(isinstance(target, ast.Name) and target.id.lstrip("_") in _LMUL_COLLECTION_NAMES
               for target in targets):
            if (isinstance(value, ast.Call) and isinstance(value.func, ast.Name)
                    and value.func.id in {"frozenset", "set", "tuple", "list"}
                    and len(value.args) == 1 and not value.keywords):
                value = value.args[0]
            if isinstance(value, (ast.Tuple, ast.List, ast.Set)):
                if (all(isinstance(item, ast.Constant) and type(item.value) in {int, float}
                        for item in value.elts)
                        and {item.value for item in value.elts} == _LMUL_VALUES):
                    return "LEGAL_LMULS"
    if isinstance(node, ast.Dict):
        for key, value in zip(node.keys, node.values):
            if (isinstance(key, ast.Constant) and isinstance(value, ast.Constant)
                    and (key.value, value.value) in {(0.125, "mf8"), ("mf8", 0.125)}):
                return "LMUL_TOKENS"
    if (isinstance(node, ast.BinOp) and isinstance(node.op, ast.FloorDiv)
            and isinstance(node.left, ast.Constant) and node.left.value == 256
            and isinstance(node.right, ast.Name) and node.right.id == "sew"):
        return "geometry.elements_per_chunk"
    return None


def main() -> int:
    violations: list[str] = []
    for root in dict.fromkeys((*BACKEND_ROOTS, TRANSITION_HANDLERS)):
        if not root.is_dir():
            violations.append(f"{root}: missing required backend directory")
    for root in BACKEND_ROOTS:
        if not root.is_dir():
            continue
        for path in python_files(root):
            relative = path.relative_to(ROOT)
            try:
                source = path.read_text(encoding="utf-8")
                tree = ast.parse(source, filename=str(path))
            except SyntaxError as exc:
                violations.append(f"{relative}:{exc.lineno}: SyntaxError: {exc.msg}")
                continue
            except UnicodeDecodeError as exc:
                violations.append(f"{relative}: UnicodeDecodeError: {exc}")
                continue
            typing_names = {"typing"}
            cast_names: set[str] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    typing_names.update(alias.asname or alias.name for alias in node.names
                                        if alias.name == "typing")
                elif isinstance(node, ast.ImportFrom) and node.module == "typing":
                    cast_names.update(alias.asname or alias.name for alias in node.names
                                      if alias.name == "cast")
            for node in ast.walk(tree):
                if isinstance(node, ast.ExceptHandler):
                    if node.type is None:
                        violations.append(f"{relative}:{node.lineno}: bare except")
                    else:
                        caught = node.type.elts if isinstance(node.type, ast.Tuple) else [node.type]
                        for exception in caught:
                            if isinstance(exception, ast.Name) and exception.id in {"Exception", "BaseException"}:
                                violations.append(f"{relative}:{node.lineno}: broad except {exception.id}")
                if isinstance(node, ast.Call):
                    function = node.func
                    if ((isinstance(function, ast.Name) and function.id in cast_names)
                            or (isinstance(function, ast.Attribute) and function.attr == "cast"
                                and isinstance(function.value, ast.Name) and function.value.id in typing_names)):
                        violations.append(f"{relative}:{node.lineno}: runtime typing.cast() in backend")
                    if (path.is_relative_to(TRANSITION_HANDLERS) and isinstance(function, ast.Attribute)
                            and (function.attr == "get_vreg_offset"
                                 or (function.attr == "get_offset" and isinstance(function.value, ast.Name)
                                     and function.value.id == "allocator"))):
                        violations.append(f"{relative}:{node.lineno}: bypasses RVV256StateView")
                literal = _inline_geometry(node)
                if literal is not None:
                    violations.append(
                        f"{relative}:{node.lineno}: inline geometry/LMUL literal {literal}; "
                        "请消费 riscv.extensions.rvv.runtime.geometry / riscv.extensions.rvv.analysis.model"
                    )
            violations.extend(_deferred_backend_imports(tree, str(relative)))
    if violations:
        print("\n".join(violations))
        return 1
    print("RVV256/RVV1024 backend quality checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
