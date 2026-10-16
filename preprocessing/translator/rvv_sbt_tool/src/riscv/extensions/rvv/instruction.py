"""RVV 指令分类和执行掩码操作数。"""

from __future__ import annotations

from riscv.frontend.model import RVInstruction


def is_vector_instruction(instruction: RVInstruction) -> bool:
    # Unsupported vector instructions must still reach the RVV rejection path.
    return instruction.opcode.startswith("v")


def is_config_instruction(instruction: RVInstruction) -> bool:
    return instruction.opcode in {"vsetvli", "vsetivli", "vsetvl"}




def peek_mask_operand(insn: RVInstruction) -> str | None:
    """查看当前指令是否显式携带 mask operand；没有则返回 ``None``。

    这里故意只做“窥视”，不做合法性判定。调用方可以先用它做 fail-fast
    路由，再由更具体的逻辑给出细节报错。

    当前识别规则保持收敛：仅当最后一个操作数字符串以 ``.t`` 结尾时才视为
    mask operand。
    """
    if not insn.operands:
        return None

    last_operand = str(insn.operands[-1]).strip().lower()
    if last_operand.endswith(".t"):
        return last_operand
    return None


def uses_explicit_v0_mask(insn: RVInstruction) -> bool:
    """判断当前指令是否使用项目当前唯一支持的 mask form：``v0.t``。

    若显式出现了其他 ``.t`` 形式，这里会直接抛出 ``ValueError``，
    交给上层统一改写成 ``UnsupportedInstructionError``。
    """
    mask_operand = peek_mask_operand(insn)
    if mask_operand is None:
        return False

    if mask_operand != "v0.t":
        raise ValueError(
            f"当前仅支持显式 v0.t masked form，实际为 {mask_operand}"
        )
    return True
