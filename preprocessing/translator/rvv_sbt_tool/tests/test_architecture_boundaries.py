"""公共模型、后端协议和唯一后端导入路径测试。"""

from __future__ import annotations

import importlib.util
import ast
from pathlib import Path
import re

import pytest

from riscv.extensions.rvv.backends.rvv1024_transition.backend import RVV1024Dispatcher
from riscv.extensions.rvv.backends.rvv256.backend import RVV256Dispatcher
from riscv.extensions.rvv.backends.rvv256.lowering import CandidateAttempt, CandidateStatus
from riscv.extensions.rvv.backends.scalar.backend import ScalarDispatcher
from riscv.extensions.rvv.translation.contracts import (
    BackendProfile,
    HandlerContext,
    InstructionSpec,
    LoweringPlan,
    LoweringResult,
    LoweringStatus,
    MaskPolicy,
    TailPolicy,
    VStartPolicy,
)
from riscv.extensions.rvv.translation.pipeline import PreparedTranslation
from riscv.extensions.rvv.translation.specs import HandlerRegistry
from riscv.extensions.rvv.runtime.access import StateAccessEmitter
from riscv.extensions.rvv.runtime.layout import SimulatedStateLayout


TOOL_ROOT = Path(__file__).resolve().parents[1]


def _production_python_files() -> tuple[Path, ...]:
    """返回翻译器生产代码，不把测试/验证脚本误当运行时实现。"""

    files = list((TOOL_ROOT / "src/riscv").rglob("*.py"))
    files.extend(
        TOOL_ROOT / name
        for name in ("rvv_sbt.py", "rvv_sbt_rvv.py", "rvv_sbt_rvv1024.py")
    )
    return tuple(sorted(files))


def test_new_backend_import_paths_expose_existing_dispatchers():
    assert ScalarDispatcher.__name__ == "ScalarDispatcher"
    assert RVV256Dispatcher.__name__ == "RVV256Dispatcher"
    assert RVV1024Dispatcher.__name__ == "RVV1024Dispatcher"


@pytest.mark.parametrize("module", ["isa_rvv", "isa_rvv256", "isa_rvv1024"])
def test_removed_backend_namespaces_are_not_importable(module):
    """旧实现目录已直接切断，不能重新引入转发壳。"""

    assert importlib.util.find_spec(module) is None


def test_handler_registry_builds_plan_and_requires_structured_result():
    registry = HandlerRegistry()

    def validator(context):
        return tuple(str(operand).strip() for operand in context.instruction.operands)

    def lowerer(context, plan):
        assert isinstance(plan, LoweringPlan)
        return LoweringResult.lowered(["    nop"])

    spec = InstructionSpec(
        opcode="vadd.vv",
        category="arithmetic",
        operand_forms=("vd, vs2, vs1",),
        supported_sews=frozenset({8, 16, 32, 64}),
        supported_lmuls=frozenset({0.5, 1.0, 2.0, 4.0, 8.0}),
        mask_policy=MaskPolicy.V0_ONLY,
        tail_policy=TailPolicy.UNDISTURBED,
        vstart_policy=VStartPolicy.CLEAR_ON_SUCCESS,
        reads_old_vd=False,
        vtype_independent=False,
        validator=validator,
        lowerer=lowerer,
        target_mnemonic="vadd.vv",
        operand_order=("vd", "vs2", "vs1"),
        signedness="modular-integer",
        rounding_policy="exact-integer",
    )
    registry.register(spec)
    assert registry.supports("vadd.vv")
    assert registry.get("vadd.vv") is spec

    from riscv.frontend.model import RVInstruction

    context = HandlerContext(
        instruction=RVInstruction(0, "vadd.vv", "v1, v2, v3", operands=["v1", "v2", "v3"]),
        state=None,
        new_label=lambda prefix: prefix,
        layout=SimulatedStateLayout(),
        temp_register_allocator=object(),
    )
    plan = registry.plan(context)
    result = registry.lower(context, plan)
    assert isinstance(result, LoweringResult)
    assert result.status is LoweringStatus.LOWERED
    assert result.assembly_lines == ("    nop",)


def test_rvv256_candidate_attempt_enforces_explicit_decision_contract():
    """跨模块 lowering 候选不能继续用含义混杂的 None 表达状态。"""

    not_applicable = CandidateAttempt(CandidateStatus.NOT_APPLICABLE)
    lowered = CandidateAttempt(CandidateStatus.LOWERED, assembly=("    nop",))
    assert not_applicable.assembly is None
    assert lowered.assembly == ("    nop",)
    with pytest.raises(RuntimeError, match="NOT_APPLICABLE"):
        CandidateAttempt(CandidateStatus.NOT_APPLICABLE, assembly=("    nop",))
    with pytest.raises(RuntimeError, match="LOWERED"):
        CandidateAttempt(CandidateStatus.LOWERED)


def test_lowering_result_has_no_legacy_sequence_surface():
    """结构化结果不能再被旧调用方隐式当作 ``list[str]`` 使用。"""

    result = LoweringResult.lowered(("    nop",))
    with pytest.raises(TypeError):
        iter(result)
    with pytest.raises(TypeError):
        len(result)
    assert not hasattr(result, "__getitem__")


def test_prepared_translation_is_factory_only_and_has_no_diagnostics_state():
    """准备结果不能由调用方伪造，也不能保存跨发射轮的诊断。"""

    with pytest.raises(TypeError, match="TranslationPipeline.prepare"):
        PreparedTranslation(program=None, analysis=None, backend_profile=None)
    assert "diagnostics" not in PreparedTranslation.__dataclass_fields__
    assert "runtime_vtype_guard" not in PreparedTranslation.__dataclass_fields__


def test_preflight_plan_index_uses_stable_source_address():
    """预检计划不能依赖本轮 Python 指令对象身份。"""

    pipeline_source = (TOOL_ROOT / "src/riscv/extensions/rvv/translation/pipeline.py").read_text(
        encoding="utf-8"
    )
    dispatch_source = (TOOL_ROOT / "src/riscv/extensions/rvv/translation/dispatch.py").read_text(
        encoding="utf-8"
    )
    assert "id(plan.instruction)" not in pipeline_source
    assert "id(insn)" not in dispatch_source
    assert "plan.instruction.address" in pipeline_source
    assert "insn.address" in dispatch_source


@pytest.mark.parametrize(
    ("field", "value"),
    (("fallback_policy", "typo"), ("preflight_policy", "typo")),
)
def test_backend_profile_rejects_unknown_runtime_policy(field, value):
    """profile 拼写错误必须在进入分析/发射前失败，不能隐式选择默认路径。"""

    values = {
        "name": "test",
        "source_vlenb": 128,
        "target_vlenb": 32,
        "fallback_policy": "raise",
        "preflight_policy": "none",
    }
    values[field] = value
    with pytest.raises(ValueError, match="未知"):
        BackendProfile(**values)


def test_handler_registry_rejects_duplicate_opcode_across_categories():
    registry = HandlerRegistry()

    def validator(context):
        return ()

    def lowerer(context, plan):
        return LoweringResult.lowered(())

    base = dict(
        opcode="vadd.vv",
        operand_forms=("vd, vs2, vs1",),
        supported_sews=frozenset({32}),
        supported_lmuls=frozenset({1.0}),
        mask_policy=MaskPolicy.FORBIDDEN,
        tail_policy=TailPolicy.AGNOSTIC,
        vstart_policy=VStartPolicy.REQUIRE_ZERO,
        reads_old_vd=False,
        vtype_independent=False,
        validator=validator,
        lowerer=lowerer,
        target_mnemonic="vadd.vv",
        operand_order=("vd", "vs2", "vs1"),
        signedness="modular-integer",
        rounding_policy="exact-integer",
    )
    registry.register(InstructionSpec(category="integer", **base))
    with pytest.raises(ValueError, match="重复注册 opcode"):
        registry.register(InstructionSpec(category="arithmetic", **base))


def test_scalar_appearance_interception_is_derived_from_registry_spec():
    """CSR 截获必须同时满足已注册 opcode 和规格 matcher，不能靠 dispatcher 白名单。"""

    class Instruction:
        opcode = "csrr"

        def __init__(self, csr: str):
            self.operands = ("a0", csr)

    rvv256 = RVV256Dispatcher().registry
    transition = RVV1024Dispatcher().registry
    for registry in (rvv256, transition):
        assert registry.handles_scalar_instruction(Instruction("vl"))
        assert not registry.handles_scalar_instruction(Instruction("cycle"))

    # 未注册 opcode 即使操作数长得像向量 CSR，也必须留在普通标量路径。
    unknown = Instruction("vl")
    unknown.opcode = "unknown-csr-form"
    assert not rvv256.handles_scalar_instruction(unknown)
    assert not transition.handles_scalar_instruction(unknown)


def test_state_access_respects_large_csr_offset_immediate_limit():
    access = StateAccessEmitter(layout=SimulatedStateLayout())
    address = access.emit_address("t0", "t6", 0x1028)
    assert "li      t0, 4136" in address
    assert "add     t0, t6, t0" in address


def test_backend_quality_gate_has_no_runtime_exception_or_state_view_bypass():
    """质量门禁脚本必须能独立检查重点后端的硬性边界。"""

    import subprocess
    import sys

    script = TOOL_ROOT / "tools/check_backend_quality.py"
    result = subprocess.run(
        [sys.executable, str(script)],
        cwd=TOOL_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_production_has_no_star_import_or_legacy_backend_reference():
    """旧命名空间和 ``import *`` 不能通过新文件重新潜入。"""

    violations: list[str] = []
    for path in _production_python_files():
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and any(
                alias.name == "*" for alias in node.names
            ):
                violations.append(f"{path.relative_to(TOOL_ROOT)}:{node.lineno}: import *")
        if re.search(r"\bisa_rvv(?:256|1024)?\b", source):
            violations.append(f"{path.relative_to(TOOL_ROOT)}: 旧 isa_rvv 命名空间")
    assert not violations, "\n".join(violations)


def test_production_has_no_legacy_protocol_or_string_diagnostic_scan():
    """结构化协议验收后不得恢复列表适配器或扫描错误注释。"""

    forbidden = (
        "from_legacy",
        "invoke_legacy_handler",
        "_lower_registered_instruction",
        "_lower_instruction_body",
        "_append_emission",
        "_call_group_emitter",
        "_looks_like_unsupported_vtype",
        "MASKED_FORM_SUPPORTED_OPCODES",
        "_template_handlers",
        "exc.__class__.__name__",
        '"# ERROR:" in',
        "'# ERROR:' in",
        '"# UNIMPLEMENTED:" in',
        "'# UNIMPLEMENTED:' in",
        '.count("# ERROR',
        ".count('# ERROR",
        '.count("# UNIMPLEMENTED',
        ".count('# UNIMPLEMENTED",
        "unsupported_vector_fallback",
        "config_handlers",
        "arithmetic_handlers",
        "memory_handlers",
        "mask_handlers",
        "csr_handlers",
        "Template = Callable[..., list[str]]",
        "模板必须返回 list[str]",
        "BACKEND_DEFINED",
        "same-as-source",
    )
    violations = []
    for path in _production_python_files():
        source = path.read_text(encoding="utf-8")
        for token in forbidden:
            if token in source:
                violations.append(f"{path.relative_to(TOOL_ROOT)}: {token}")
    assert not violations, "\n".join(violations)


def test_backend_lowering_metadata_accessors_reject_foreign_specs():
    """lowerer 不能用 cast 掩盖跨 registry metadata 混用。"""

    from riscv.extensions.rvv.backends.rvv256.lowering_metadata import (
        lowering_metadata as rvv256_metadata,
    )
    from riscv.extensions.rvv.backends.rvv1024_transition.lowering_metadata import (
        lowering_metadata as transition_metadata,
    )

    rvv256_spec = RVV256Dispatcher().registry.require("vadd.vv")
    transition_spec = RVV1024Dispatcher().registry.require("vadd.vv")
    assert rvv256_metadata(rvv256_spec).builder is not None
    assert transition_metadata(transition_spec).builder is not None
    with pytest.raises(TypeError, match="不属于 RVV256"):
        rvv256_metadata(transition_spec)
    with pytest.raises(TypeError, match="不属于 RVV1024"):
        transition_metadata(rvv256_spec)


def test_transition_handlers_cannot_use_128_byte_vreg_layout():
    """RVV1024 handler 的 32B payload 地址只能由 state_view 计算。"""

    violations = []
    handlers = TOOL_ROOT / "src/riscv/extensions/rvv/backends/rvv1024_transition/handlers"
    for path in handlers.rglob("*.py"):
        source = path.read_text(encoding="utf-8")
        if "allocator.get_offset" in source or ".get_vreg_offset(" in source:
            violations.append(str(path.relative_to(TOOL_ROOT)))
    assert not violations, "\n".join(violations)


def test_state_tracker_has_one_actual_definition_module():
    """状态追踪器不能在 ``middle_end`` 留一份实现再由 ``core.state`` 转发。"""

    assert (TOOL_ROOT / "src/riscv/extensions/rvv/analysis/config.py").exists()
    assert not (TOOL_ROOT / "core/middle_end/state_tracker.py").exists()
    for path in _production_python_files():
        source = path.read_text(encoding="utf-8")
        assert "core.middle_end.state_tracker" not in source, str(path)


def test_riscv_and_rvv_dependencies_follow_ownership():
    """Common RISC-V modules cannot depend on an extension or its backends."""
    files = tuple((TOOL_ROOT / "src/riscv").rglob("*.py"))
    assert len(files) > 50
    violations = []
    for path in files:
        relative = path.relative_to(TOOL_ROOT / "src/riscv")
        own_backend = relative.parts[3] if relative.parts[:3] == ("extensions", "rvv", "backends") else None
        for node in ast.walk(ast.parse(path.read_text())):
            modules = ([node.module or ""] if isinstance(node, ast.ImportFrom)
                       else [a.name for a in node.names] if isinstance(node, ast.Import) else [])
            for module in modules:
                if relative.parts[0] != "extensions" and module.startswith("riscv.extensions"):
                    violations.append(f"{relative}: {module}")
                if module.startswith("riscv.extensions.rvv.backends"):
                    if own_backend is None or not module.startswith(f"riscv.extensions.rvv.backends.{own_backend}"):
                        violations.append(f"{relative}: {module}")
    assert not violations, "\n".join(violations)


def test_dispatchers_expose_only_context_plan_lower_protocol():
    """删除会绕开统一 emitter 编排的旧 ``dispatcher.dispatch`` facade。"""

    for dispatcher_type in (
        ScalarDispatcher,
        RVV256Dispatcher,
        RVV1024Dispatcher,
    ):
        assert not hasattr(dispatcher_type, "dispatch")
        assert hasattr(dispatcher_type, "make_context")
        assert hasattr(dispatcher_type, "plan")
        assert hasattr(dispatcher_type, "lower")


def test_production_has_no_assembly_marker_control_protocol():
    """状态收尾次序只能用 ``AssemblyFragments`` 表达，不能扫描注释标记。"""

    forbidden = (
        "CHIMERA_SEMANTIC_T6_RESULT_AFTER_STATE_POSTAMBLE",
        "CHIMERA_VSTART_CLEAR_BEFORE_SEMANTIC_T6_RESULT",
        "backends.scalar.temp_regs",
    )
    violations = []
    for path in _production_python_files():
        source = path.read_text(encoding="utf-8")
        for token in forbidden:
            if token in source:
                violations.append(f"{path.relative_to(TOOL_ROOT)}: {token}")
    assert not violations, "\n".join(violations)


def test_opcode_assembly_builders_only_accept_bound_context():
    """私有汇编 builder 也不能保留旧四参数兼容入口。

    builder 返回汇编行并不等于正式 handler 返回列表；正式 handler 是 registry
    中的结构化 lowerer。这里锁定二者之间唯一允许的内部边界。
    """

    violations = []
    builder_count = 0
    for path in (TOOL_ROOT / "src/riscv/extensions/rvv/backends").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not (node.name.startswith("_build_") and node.name.endswith("_lines")):
                continue
            builder_count += 1
            arguments = tuple(argument.arg for argument in node.args.args)
            if arguments != ("context",):
                violations.append(
                    f"{path.relative_to(TOOL_ROOT)}:{node.lineno}: "
                    f"{node.name}{arguments}"
                )
    assert builder_count > 0
    assert not violations, "\n".join(violations)


def test_removed_cli_flags_and_hardcoded_openblas_paths_stay_removed():
    """只保留真实生效的 CLI 参数，资产解析不能依赖仓库内大目录。"""

    source = "\n".join(
        path.read_text(encoding="utf-8") for path in _production_python_files()
    )
    for flag in ("--jal-range-fixup", "--wide-lmul", "--conservative-lmul"):
        assert re.search(rf"['\"]{re.escape(flag)}['\"]", source) is None
    assert "openblas-function/OpenBLAS" not in source
    assert "openblas_build_rvv" not in source


def test_backend_handler_modules_stay_below_size_boundary():
    """大模块回归必须在代码评审前失败。"""

    oversized = []
    for path in (TOOL_ROOT / "src/riscv/extensions/rvv/backends").rglob("*.py"):
        if "handlers" not in path.parts:
            continue
        line_count = len(path.read_text(encoding="utf-8").splitlines())
        if line_count > 3000:
            oversized.append(f"{path.relative_to(TOOL_ROOT)}: {line_count}")
    assert not oversized, "\n".join(oversized)


def test_all_backend_registries_have_concrete_forms_and_unique_metadata():
    """文档、dispatcher 和 lowering 必须能从 registry 得到完整事实。"""

    registries = (
        ScalarDispatcher().registry,
        RVV256Dispatcher(wide_lmul=False).registry,
        RVV256Dispatcher(wide_lmul=True).registry,
        RVV1024Dispatcher().registry,
    )
    for registry in registries:
        opcodes = [spec.opcode for spec in registry]
        assert len(opcodes) == len(set(opcodes))
        for spec in registry:
            assert spec.operand_forms
            assert all("专用 validator form" not in form for form in spec.operand_forms)
            assert callable(spec.validator)
            assert callable(spec.lowerer)
            assert spec.target_mnemonic
            assert spec.operand_order
            assert spec.signedness not in {
                "backend-defined", "opcode-explicit", "handler-explicit"
            }
            assert spec.rounding_policy not in {
                "backend-defined", "opcode-explicit-vxrm-or-exact"
            }


def test_program_emitter_is_the_only_top_level_emitter_facade():
    source = (TOOL_ROOT / "src/riscv/extensions/rvv/translation/emitter.py").read_text(encoding="utf-8")
    assert "class ProgramEmitter" in source
    assert "    def emit(" in source
    assert "    def generate_program(" not in source
    assert "    def generate(" not in source
    assert "    def generate_function(" not in source
    assert "    def generate_translated_function(" not in source
    assert "_emit_tls_state_definition" not in source
    assert "class AsmEmitter" not in source
    assert not (TOOL_ROOT / "core/state/access.py").exists()
    for cli_name in ("rvv_sbt_rvv.py", "rvv_sbt_rvv1024.py"):
        cli_source = (TOOL_ROOT / cli_name).read_text(encoding="utf-8")
        assert "class Emitter(ProgramEmitter)" not in cli_source


def test_public_translation_apis_do_not_bypass_pipeline_prepare():
    """三条 CLI/API 不能重新出现直接 ``generate_function`` 快路径。"""

    for name in ("rvv_sbt.py", "rvv_sbt_rvv.py", "rvv_sbt_rvv1024.py"):
        source = (TOOL_ROOT / name).read_text(encoding="utf-8")
        assert "TranslationPipeline(" in source
        assert ".prepare(" in source
        assert ".generate_function(" not in source


def test_generated_support_document_matches_all_registries():
    from tools.generate_support_docs import DOC_PATH, render

    assert DOC_PATH.read_text(encoding="utf-8") == render()


def test_pytest_modules_have_no_manual_drivers_or_debug_prints():
    """pytest 文件只声明用例；人工程序应位于 ``examples`` 或 ``verify``。"""

    violations = []
    for path in sorted((TOOL_ROOT / "tests").glob("test_*.py")):
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.If):
                test_nodes = tuple(ast.walk(node.test))
                has_name_guard = any(
                    isinstance(item, ast.Name) and item.id == "__name__"
                    for item in test_nodes
                )
                has_main_literal = any(
                    isinstance(item, ast.Constant) and item.value == "__main__"
                    for item in test_nodes
                )
                if has_name_guard and has_main_literal:
                    violations.append(f"{path.name}:{node.lineno}: __main__")
            if isinstance(node, ast.FunctionDef) and node.name == "run_all_tests":
                violations.append(f"{path.name}:{node.lineno}: run_all_tests")
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "print"
            ):
                violations.append(f"{path.name}:{node.lineno}: print")
    assert not violations, "\n".join(violations)
