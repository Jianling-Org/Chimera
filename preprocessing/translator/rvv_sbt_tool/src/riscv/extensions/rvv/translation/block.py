"""单条向量翻译块的现场保护与状态基址发射。

本组件只消费 ``LoweringResult`` 中的结构化语义信息：它不会
扫描汇编注释判断成功/失败，也不会反解析指令的目的操作数
来推测 clobber（破坏寄存器）。``sp``/``t6`` 的文本替换仅用于
保留客体输入别名，不参与能力或状态判定。
"""

from __future__ import annotations

import re
from typing import Any, Iterable

from riscv.registers import normalize_fpr_name, normalize_gpr_name
from riscv.extensions.rvv.translation.contracts import LoweringResult
from riscv.extensions.rvv.runtime.access import STATE_BASE_MARKER, StateAccessEmitter


class VectorBlockEmitter:
    """依据结构化降低结果包裹单条 RVV 翻译块。"""

    protected_gprs = (
        "t0", "t1", "t2", "t3", "t4", "t5", "t6",
        "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
    )
    protected_fprs = (
        "fa0", "fa1", "fa2", "fa3", "fa4", "fa5", "fa6", "fa7",
        "ft0", "ft1", "ft2", "ft3", "ft4", "ft5",
        "ft6", "ft7", "ft8", "ft9", "ft10", "ft11",
    )

    _sp_pattern = re.compile(
        r"(?<![A-Za-z0-9_.])(?:sp|x2)(?![A-Za-z0-9_.])"
    )
    _semantic_t6_pattern = re.compile(
        r"(?<![A-Za-z0-9_.])(?:t6|x31)(?![A-Za-z0-9_.])"
    )
    _internal_stack_marker = "CHIMERA_INTERNAL_STACK"
    _state_base_marker = STATE_BASE_MARKER

    def __init__(self, state_access: StateAccessEmitter):
        self.state_access = state_access

    @staticmethod
    def _compute_spill_frame_size(
        gprs: Iterable[str], fprs: Iterable[str], result_slots: int = 0,
    ) -> int:
        """按 RV64 ABI 的 16 字节栈对齐计算局部保护帧。"""

        raw_size = (len(tuple(gprs)) + len(tuple(fprs)) + result_slots) * 8
        return ((raw_size + 15) // 16) * 16

    @staticmethod
    def _line_uses_t6_as_state_base(code_part: str) -> bool:
        """识别历史模板中 ``dst = t6 + offset`` 的状态地址形式。"""

        return re.match(
            r"^\s*add\s+[A-Za-z][A-Za-z0-9]*\s*,\s*t6\s*,", code_part
        ) is not None

    @staticmethod
    def _line_writes_t6(code_part: str) -> bool:
        """识别将 ``t6/x31`` 作为客体语义输出的行。"""

        return re.match(
            r"^\s*[A-Za-z.0-9]+\s+(?:t6|x31)\s*,", code_part
        ) is not None

    def _replace_semantic_t6_uses(
        self, translated: list[str], alias: str
    ) -> list[str]:
        """把客体 ``t6`` 输入改写到别名，保留真实状态基址访问。"""

        replaced: list[str] = []
        for line in translated:
            if self._state_base_marker in line:
                replaced.append(line)
                continue
            if "#" in line:
                code_part, comment_part = line.split("#", 1)
                if (
                    self._line_uses_t6_as_state_base(code_part)
                    or self._line_writes_t6(code_part)
                ):
                    replaced.append(line)
                else:
                    replaced.append(
                        f"{self._semantic_t6_pattern.sub(alias, code_part)}#{comment_part}"
                    )
            elif self._line_uses_t6_as_state_base(line) or self._line_writes_t6(line):
                replaced.append(line)
            else:
                replaced.append(self._semantic_t6_pattern.sub(alias, line))
        return replaced

    def _replace_stack_pointer_uses(
        self, translated: list[str], alias: str
    ) -> list[str]:
        """把客体 ``sp/x2`` 访问改写为保存的原始栈指针别名。"""

        replaced: list[str] = []
        for line in translated:
            if self._internal_stack_marker in line:
                replaced.append(line)
                continue
            if "#" in line:
                code_part, comment_part = line.split("#", 1)
                replaced.append(
                    f"{self._sp_pattern.sub(alias, code_part)}#{comment_part}"
                )
            else:
                replaced.append(self._sp_pattern.sub(alias, line))
        return replaced

    def wrap(
        self,
        insn: Any,
        result: LoweringResult,
        *,
        tls_state: bool = True,
    ) -> list[str]:
        """为一条已降低指令发射局部 save/restore 保护块。"""

        if not isinstance(result, LoweringResult):
            raise TypeError("VectorBlockEmitter.wrap 只接受 LoweringResult")

        translated = list(result.assembly_lines)
        semantic_gpr_inputs = {
            normalized
            for register in result.semantic_inputs
            if (normalized := normalize_gpr_name(register)) is not None
        }
        semantic_fpr_inputs = {
            normalized
            for register in result.semantic_inputs
            if (normalized := normalize_fpr_name(register)) is not None
        }
        semantic_gpr_outputs = {
            normalized
            for register in result.semantic_outputs
            if (normalized := normalize_gpr_name(register)) is not None
        }
        semantic_fpr_outputs = {
            normalized
            for register in result.semantic_outputs
            if (normalized := normalize_fpr_name(register)) is not None
        }
        clobbered_gprs = [
            register
            for register in self.protected_gprs
            if register in result.clobbered_gprs
            and register not in semantic_gpr_outputs
        ]
        clobbered_fprs = [
            register
            for register in self.protected_fprs
            if register in result.clobbered_fprs
            and register not in semantic_fpr_outputs
        ]
        needs_state_base = bool(result.state_reads or result.state_writes)

        original_sp_alias: str | None = None
        writes_sp = "sp" in semantic_gpr_outputs
        if "sp" in semantic_gpr_inputs or writes_sp:
            blocked = (
                set(clobbered_gprs)
                | semantic_gpr_inputs
                | semantic_gpr_outputs
                | {"t6"}
            )
            original_sp_alias = next(
                (register for register in self.protected_gprs if register not in blocked),
                None,
            )
            if original_sp_alias is None:
                raise RuntimeError(
                    "无法为翻译块保留原始 sp: "
                    f"{insn.opcode} {insn.op_str}"
                )
            translated = self._replace_stack_pointer_uses(
                translated, original_sp_alias
            )
            clobbered_gprs.append(original_sp_alias)

        semantic_t6_alias: str | None = None
        if needs_state_base and "t6" in semantic_gpr_inputs:
            blocked = (
                set(clobbered_gprs)
                | semantic_gpr_inputs
                | semantic_gpr_outputs
                | {"t6"}
            )
            semantic_t6_alias = next(
                (register for register in self.protected_gprs if register not in blocked),
                None,
            )
            if semantic_t6_alias is None:
                raise RuntimeError(
                    "无法为翻译块保留原始 t6 输入: "
                    f"{insn.opcode} {insn.op_str}"
                )
            translated = self._replace_semantic_t6_uses(
                translated, semantic_t6_alias
            )
            clobbered_gprs.append(semantic_t6_alias)

        # t6 在正文中可以只读，但块头基址序列会覆盖它。
        if (
            needs_state_base
            and "t6" not in semantic_gpr_outputs
            and "t6" not in clobbered_gprs
        ):
            clobbered_gprs.append("t6")
        # 同一物理寄存器同时是客体输入和输出时，块头仍需
        # 保存其原值，块尾则必须保留新结果。
        for register in semantic_gpr_inputs & semantic_gpr_outputs:
            if register == "sp":
                continue
            if register not in clobbered_gprs:
                clobbered_gprs.append(register)

        state_base_calls_helper = (
            needs_state_base
            and self.state_access.calls_helper(tls_state=tls_state)
        )
        if state_base_calls_helper:
            for register in self.state_access.call_clobbered_gprs:
                if (
                    register not in semantic_gpr_outputs
                    and register not in clobbered_gprs
                ):
                    clobbered_gprs.append(register)
            for register in self.state_access.call_clobbered_fprs:
                if (
                    register not in semantic_fpr_outputs
                    and register not in clobbered_fprs
                ):
                    clobbered_fprs.append(register)

        if not clobbered_gprs and not clobbered_fprs:
            if not needs_state_base:
                return translated
            return [
                "    # 块内重新加载 simulated_cpu_state 基地址到 t6",
                *self.state_access.emit_base_load(tls_state=tls_state),
                *translated,
            ]

        spill_frame_size = self._compute_spill_frame_size(
            clobbered_gprs, clobbered_fprs, result_slots=int(writes_sp),
        )
        lines = [
            f"    # 保存 RVV 翻译块现场: {insn.opcode}",
            f"    addi    sp, sp, -{spill_frame_size}",
        ]

        stack_offset = 0
        gpr_spill_offsets: dict[str, int] = {}
        fpr_spill_offsets: dict[str, int] = {}
        for register in clobbered_gprs:
            gpr_spill_offsets[register] = stack_offset
            lines.append(f"    sd      {register}, {stack_offset}(sp)")
            stack_offset += 8
        for register in clobbered_fprs:
            fpr_spill_offsets[register] = stack_offset
            lines.append(f"    fsd     {register}, {stack_offset}(sp)")
            stack_offset += 8

        if needs_state_base:
            lines.append("    # 块内重新加载 simulated_cpu_state 基地址到 t6")
            lines.extend(self.state_access.emit_base_load(tls_state=tls_state))
            if semantic_t6_alias and "t6" in gpr_spill_offsets:
                lines.append("    # 恢复源指令作为输入使用的原始 t6")
                lines.append(
                    f"    ld      {semantic_t6_alias}, "
                    f"{gpr_spill_offsets['t6']}(sp)"
                )

            if state_base_calls_helper:
                gpr_inputs_to_restore = [
                    register
                    for register in semantic_gpr_inputs
                    if register != "t6" and register in gpr_spill_offsets
                ]
                fpr_inputs_to_restore = [
                    register
                    for register in semantic_fpr_inputs
                    if register in fpr_spill_offsets
                ]
                if gpr_inputs_to_restore or fpr_inputs_to_restore:
                    lines.append("    # 恢复 TLS helper 可能破坏的原始标量输入")
                for register in gpr_inputs_to_restore:
                    lines.append(
                        f"    ld      {register}, "
                        f"{gpr_spill_offsets[register]}(sp)"
                    )
                for register in fpr_inputs_to_restore:
                    lines.append(
                        f"    fld     {register}, "
                        f"{fpr_spill_offsets[register]}(sp)"
                    )

        if original_sp_alias and "sp" in semantic_gpr_inputs:
            lines.append("    # 保留原程序 sp 作为向量访存基址")
            lines.append(
                f"    addi    {original_sp_alias}, sp, {spill_frame_size}"
            )
        lines.extend(translated)

        # Keep the old frame address until every borrowed register is restored.
        # The final load reads its address before committing the guest sp result.
        sp_result_offset = (len(clobbered_gprs) + len(clobbered_fprs)) * 8
        if writes_sp:
            lines.append(f"    sd      {original_sp_alias}, {sp_result_offset}(sp)")

        lines.append(f"    # 恢复 RVV 翻译块现场: {insn.opcode}")
        restore_offset = len(clobbered_gprs) * 8
        for register in clobbered_fprs:
            if register not in semantic_fpr_outputs:
                lines.append(f"    fld     {register}, {restore_offset}(sp)")
            restore_offset += 8

        restore_offset = 0
        for register in clobbered_gprs:
            if register not in semantic_gpr_outputs:
                lines.append(f"    ld      {register}, {restore_offset}(sp)")
            restore_offset += 8
        if writes_sp:
            lines.append(f"    ld      sp, {sp_result_offset}(sp)")
        else:
            lines.append(f"    addi    sp, sp, {spill_frame_size}")
        return lines


__all__ = ["VectorBlockEmitter"]
