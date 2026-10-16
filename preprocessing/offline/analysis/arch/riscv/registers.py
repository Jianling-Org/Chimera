"""RISC-V scalar registers and instruction-spelling constants."""

from __future__ import annotations

import re


ADDRESS_OPERAND_RE = re.compile(
    r"(-?(?:0x[0-9a-f]+|\d+))?\(([\w]+)\)",
    re.IGNORECASE,
)
WHOLE_REGISTER_ACCESS_RE = re.compile(
    r"^(?:vl(?:1|2|4|8)r(?:e\d+)?|vs(?:1|2|4|8)r)\.v$",
    re.IGNORECASE,
)
REGISTER_ALIASES = {
    "x0": "zero", "x1": "ra", "x2": "sp", "x3": "gp", "x4": "tp",
    "x5": "t0", "x6": "t1", "x7": "t2", "x8": "s0", "x9": "s1",
    "x10": "a0", "x11": "a1", "x12": "a2", "x13": "a3",
    "x14": "a4", "x15": "a5", "x16": "a6", "x17": "a7",
    "x18": "s2", "x19": "s3", "x20": "s4", "x21": "s5",
    "x22": "s6", "x23": "s7", "x24": "s8", "x25": "s9",
    "x26": "s10", "x27": "s11", "x28": "t3", "x29": "t4",
    "x30": "t5", "x31": "t6", "fp": "s0",
}
SCALAR_REGISTERS = set(REGISTER_ALIASES) | set(REGISTER_ALIASES.values())
CALLER_SAVED = {
    "ra", "t0", "t1", "t2", "t3", "t4", "t5", "t6",
    "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
}
NO_DESTINATION = {
    "ret", "jr", "j", "beq", "bne", "blt", "bge", "bltu", "bgeu",
    "beqz", "bnez", "bltz", "bgez", "blez", "bgtz", "ecall",
    "ebreak", "fence", "fence.i", "sfence.vma", "pause", "wfi",
}
SCALAR_STORES = {
    "sd", "sw", "sh", "sb", "fsd", "fsw", "c.sd", "c.sw", "c.fsd",
    "c.fsw", "c.sdsp", "c.swsp", "c.fsdsp", "c.fswsp",
}


def canonical_register(register: str) -> str:
    return REGISTER_ALIASES.get(register.lower(), register.lower())
