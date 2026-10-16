"""Translation-variant external Translator command adapter."""

from __future__ import annotations

from typing import Sequence

from ..core.contracts import TranslatorFormat


class ExternalTranslator:
    def __init__(self, *, python: str) -> None:
        self._python = python
        # Match emitted assembler symbols, including $ in C++ lambda names.
        self._format = TranslatorFormat(
            target_label_prefix="branch_j_target_",
            entry_label_suffix="_translated",
            label_pattern=r"^\s*([A-Za-z_.$][A-Za-z0-9_.$]*):\s*(?:#.*)?$",
        )

    @property
    def format(self) -> TranslatorFormat:
        return self._format

    def command(self, request) -> Sequence[str]:
        if not request.translator_path.is_file():
            raise FileNotFoundError(
                "selected translator is no longer an existing file: "
                f"{request.translator_path}"
            )
        return [
            self._python,
            str(request.translator_path),
            str(request.native_dump),
            request.symbol_namespace,
            "-o",
            str(request.assembly_output),
        ]
