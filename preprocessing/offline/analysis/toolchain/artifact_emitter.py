"""Target-owned emitters for small assembly-backed ABI artifacts."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
import re


def _safe_symbol(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "_", value)


class GnuArtifactEmitter:
    """Emit 64-bit tables and provenance for a GNU-compatible assembler.

    The word directive is deliberately configurable.  ``.quad`` is accepted
    by the host GNU assembler; a target may select another spelling through
    the same emitter implementation.
    """

    def __init__(self, *, word_directive: str = ".quad") -> None:
        if not re.fullmatch(r"\.[A-Za-z][A-Za-z0-9_.]*", word_directive):
            raise ValueError(f"invalid assembler word directive: {word_directive!r}")
        self.word_directive = word_directive

    @staticmethod
    def _row_values(row: object) -> tuple[int, ...]:
        if isinstance(row, int) and not isinstance(row, bool):
            values = (row,)
        else:
            try:
                values = tuple(row)  # type: ignore[arg-type]
            except TypeError as error:
                raise TypeError("artifact table rows must be integers or iterables") from error
        for value in values:
            if not isinstance(value, int) or isinstance(value, bool):
                raise TypeError("artifact table values must be integers")
            if not 0 <= value < 2**64:
                raise ValueError("artifact table value does not fit u64")
        return values

    def emit_u64_table(
        self,
        output_path: Path,
        tables: Iterable[tuple[str, Iterable[object]]],
    ) -> None:
        """Write ordered named symbols whose rows contain u64 values.

        Rows are iterated exactly once, so callers may provide generators for
        large mapping tables without constructing another flattened list.
        """
        destination = Path(output_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("w", encoding="utf-8", newline="\n") as output:
            output.write("# Generated Chimera ABI u64 table.\n")
            output.write(".section .rodata\n")
            output.write(".balign 8\n\n")
            for symbol, rows in tables:
                if not isinstance(symbol, str) or not re.fullmatch(
                    r"[A-Za-z_][A-Za-z0-9_]*", symbol
                ):
                    raise ValueError(f"invalid artifact symbol: {symbol!r}")
                output.write(f".globl {symbol}\n{symbol}:\n")
                for row in rows:
                    values = self._row_values(row)
                    if values:
                        output.write(
                            f"    {self.word_directive} "
                            + ", ".join(
                                str(value) if value in (0, 1)
                                else f"0x{value:016x}"
                                for value in values
                            )
                            + "\n"
                        )
                output.write("\n")

    def emit_translation_provenance(
        self,
        output_path: Path,
        *,
        symbol_namespace: str,
        fingerprint: str,
    ) -> None:
        """Write the two symbols used to identify a translated-code DSO."""
        safe_namespace = _safe_symbol(symbol_namespace)
        if not safe_namespace or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", safe_namespace):
            raise ValueError(f"invalid translation symbol namespace: {symbol_namespace!r}")
        if not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
            raise ValueError("translation fingerprint must be a lowercase SHA-256")
        destination = Path(output_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        abi_symbol = f"chimera_{safe_namespace}_translated_code_abi_v1"
        fingerprint_symbol = (
            f"chimera_{safe_namespace}_translation_fingerprint_{fingerprint}"
        )
        with destination.open("w", encoding="utf-8", newline="\n") as output:
            output.write(".section .rodata\n")
            # ``.balign`` takes a byte alignment.  The old ``.align 3``
            # spelling is target/toolchain dependent and is rejected by the
            # GNU assembler on some hosts (where the argument is a power of
            # two rather than a log2 value).
            output.write(".balign 8\n")
            output.write(f".globl {abi_symbol}\n{abi_symbol}:\n")
            output.write("  .quad 1\n")
            output.write(
                f".globl {fingerprint_symbol}\n{fingerprint_symbol}:\n"
            )
            output.write("  .byte 0\n")


__all__ = ["GnuArtifactEmitter"]
