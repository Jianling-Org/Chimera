"""RISC-V register names and explicit operand register uses."""

import re
from riscv.frontend.model import RVInstruction

_X_TO_ABI = {
    "x0": "zero",
    "x1": "ra",
    "x2": "sp",
    "x3": "gp",
    "x4": "tp",
    "x5": "t0",
    "x6": "t1",
    "x7": "t2",
    "x8": "s0",
    "x9": "s1",
    "x10": "a0",
    "x11": "a1",
    "x12": "a2",
    "x13": "a3",
    "x14": "a4",
    "x15": "a5",
    "x16": "a6",
    "x17": "a7",
    "x18": "s2",
    "x19": "s3",
    "x20": "s4",
    "x21": "s5",
    "x22": "s6",
    "x23": "s7",
    "x24": "s8",
    "x25": "s9",
    "x26": "s10",
    "x27": "s11",
    "x28": "t3",
    "x29": "t4",
    "x30": "t5",
    "x31": "t6",
}

# `fp` 是 `s0` 的 ABI 别名，这里也归并掉，避免解析时出现两个名字代表一个寄存器。
_ABI_GPRS = {
    "zero", "ra", "sp", "gp", "tp",
    "t0", "t1", "t2", "t3", "t4", "t5", "t6",
    "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11",
    "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
}

_F_TO_ABI = {
    "f0": "ft0",
    "f1": "ft1",
    "f2": "ft2",
    "f3": "ft3",
    "f4": "ft4",
    "f5": "ft5",
    "f6": "ft6",
    "f7": "ft7",
    "f8": "fs0",
    "f9": "fs1",
    "f10": "fa0",
    "f11": "fa1",
    "f12": "fa2",
    "f13": "fa3",
    "f14": "fa4",
    "f15": "fa5",
    "f16": "fa6",
    "f17": "fa7",
    "f18": "fs2",
    "f19": "fs3",
    "f20": "fs4",
    "f21": "fs5",
    "f22": "fs6",
    "f23": "fs7",
    "f24": "fs8",
    "f25": "fs9",
    "f26": "fs10",
    "f27": "fs11",
    "f28": "ft8",
    "f29": "ft9",
    "f30": "ft10",
    "f31": "ft11",
}

_ABI_FPRS = {
    "ft0", "ft1", "ft2", "ft3", "ft4", "ft5", "ft6", "ft7", "ft8", "ft9", "ft10", "ft11",
    "fs0", "fs1", "fs2", "fs3", "fs4", "fs5", "fs6", "fs7", "fs8", "fs9", "fs10", "fs11",
    "fa0", "fa1", "fa2", "fa3", "fa4", "fa5", "fa6", "fa7",
}

# 向量寄存器单独识别并排除，避免误把 `v8` 这种 token 当作普通标量寄存器。
_VECTOR_REGISTER_RE = re.compile(r"^v(?:[0-9]|[12][0-9]|3[01])$")


def _tokenize_register_candidates(text: str) -> list[str]:
    """
    把一段操作数字符串切成 token。

    这里故意不用宽松的 “单词提取” 正则，因为像 `0x1` 这种立即数里会错误拆出 `x1`。
    按分隔符切分，并保留点和下划线以避免拆开符号名：
    - `(a0)` -> `a0`
    - `0x1`  -> `0x1`
    - `8(sp)` -> `8`, `sp`
    """
    return [token for token in re.split(r"[^A-Za-z0-9_.]+", text) if token]


def _normalize_gpr_name(token: str) -> str | None:
    """
    归一化 GPR 名称到 ABI 形式。

    返回值示例：
    - `x5` -> `t0`
    - `fp` -> `s0`
    - `a0` -> `a0`
    - 其他非 GPR token -> None
    """
    lowered = token.lower()
    if lowered == "fp":
        return "s0"
    if lowered in _X_TO_ABI:
        return _X_TO_ABI[lowered]
    if lowered in _ABI_GPRS:
        return lowered
    return None


def _normalize_fpr_name(token: str) -> str | None:
    """
    归一化 FPR 名称到 ABI 形式。

    返回值示例：
    - `f0` -> `ft0`
    - `fa0` -> `fa0`
    - 其他非 FPR token -> None
    """
    lowered = token.lower()
    if lowered in _F_TO_ABI:
        return _F_TO_ABI[lowered]
    if lowered in _ABI_FPRS:
        return lowered
    return None


def normalize_gpr_name(token: str) -> str | None:
    """公开的 ABI GPR 归一化入口，供结构化语义集合复用。"""

    return _normalize_gpr_name(str(token).strip())


def normalize_fpr_name(token: str) -> str | None:
    """公开的 ABI FPR 归一化入口，供结构化语义集合复用。"""

    return _normalize_fpr_name(str(token).strip())


def collect_scalar_register_uses(insn: RVInstruction) -> tuple[set[str], set[str]]:
    """
    收集当前指令显式提到的标量寄存器。

    这一步只做“寄存器占用识别”，不判断它是输入还是输出；
    对 temp allocator 而言，只要语义里已经用到了，就应该避免拿来当中间寄存器。

    为了尽量稳妥，这里同时检查：
    - `insn.operands`：结构化操作数字段；
    - `insn.op_str`：原始操作数字符串。
    """
    gprs: set[str] = set()
    fprs: set[str] = set()

    texts: list[str] = [insn.op_str]
    texts.extend(str(operand) for operand in insn.operands)

    for text in texts:
        for token in _tokenize_register_candidates(text):
            lowered = token.lower()

            # 先过滤向量寄存器，避免 `v8` 进入后续标量归一化流程。
            if _VECTOR_REGISTER_RE.match(lowered):
                continue

            normalized_gpr = _normalize_gpr_name(lowered)
            if normalized_gpr is not None:
                gprs.add(normalized_gpr)
                continue

            normalized_fpr = _normalize_fpr_name(lowered)
            if normalized_fpr is not None:
                fprs.add(normalized_fpr)

    return gprs, fprs


CALL_CLOBBERED_GPRS = (
    "ra",
    "t0", "t1", "t2", "t3", "t4", "t5", "t6",
    "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
)
CALL_CLOBBERED_FPRS = (
    "fa0", "fa1", "fa2", "fa3", "fa4", "fa5", "fa6", "fa7",
    "ft0", "ft1", "ft2", "ft3", "ft4", "ft5",
    "ft6", "ft7", "ft8", "ft9", "ft10", "ft11",
)
