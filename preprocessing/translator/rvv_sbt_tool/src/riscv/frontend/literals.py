"""Integer literals accepted by the symbolic assembly inputs."""

import re


def parse_integer_literal(value: str) -> int:
    """Parse GNU assembler radix prefixes, including leading-zero octal."""
    text = str(value).strip()
    if re.fullmatch(r"[+-]?(?:0[xX][0-9a-fA-F]+|0[bB][01]+|0[0-7]*|[1-9][0-9]*)", text) is None:
        raise ValueError(f"Invalid assembly integer literal: {value!r}")
    digits = text[1:] if text[:1] in {"+", "-"} else text
    if digits.lower().startswith("0x"):
        base = 16
    elif digits.lower().startswith("0b"):
        base = 2
    else:
        base = 8 if digits.startswith("0") else 10
    return int(text, base)
