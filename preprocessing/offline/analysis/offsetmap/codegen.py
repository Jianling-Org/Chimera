"""Generate variant-namespaced Offset-map ABI v1 address maps."""

from __future__ import annotations

import json
from pathlib import Path
import re

OFFSET_MAP_ABI_VERSION = 1


def parse_asm_source(path: str | Path, translator_format) -> dict[str, int]:
    label_pattern = re.compile(translator_format.label_pattern)
    target_pattern = re.compile(
        re.escape(translator_format.target_label_prefix) + r"([0-9a-fA-F]+)"
    )
    translated_to_original: dict[str, int] = {}
    pending_translated: str | None = None

    for line in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines():
        match = label_pattern.match(line)
        if match is None:
            continue
        label = match.group(1)
        if label.endswith(translator_format.entry_label_suffix):
            pending_translated = label
            continue
        target = target_pattern.fullmatch(label)
        if target is not None and pending_translated is not None:
            translated_to_original[pending_translated] = int(target.group(1), 16)
            pending_translated = None

    return translated_to_original


def parse_translated_dump(
    path: str | Path,
    translated_to_original: dict[str, int],
    translator_format,
    disassembly_format,
) -> dict[int, int]:
    dump_label_pattern = re.compile(disassembly_format.dump_label_pattern)
    target_pattern = re.compile(
        re.escape(translator_format.target_label_prefix) + r"([0-9a-fA-F]+)"
    )
    mapping: dict[int, int] = {}
    for line in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines():
        match = dump_label_pattern.search(line)
        if match is None:
            continue
        translated_address = int(match.group(1), 16)
        label = match.group(2)
        branch_target = target_pattern.fullmatch(label)
        if branch_target is not None:
            mapping[int(branch_target.group(1), 16)] = translated_address
        elif (
            label.endswith(translator_format.entry_label_suffix)
            and label in translated_to_original
        ):
            mapping[translated_to_original[label]] = translated_address
    return mapping


def export_asm(
    mapping: dict[int, int],
    output_path: str | Path,
    module_name: str,
    *,
    emitter=None,
) -> None:
    """Emit an offset-map table through the target-selected emitter."""
    symbol = _safe_symbol(module_name)
    prefix = f"chimera_{symbol}"
    forward = sorted(mapping.items())
    reverse = sorted((translated, original) for original, translated in mapping.items())
    if emitter is None or not callable(getattr(emitter, "emit_u64_table", None)):
        raise RuntimeError(
            "offset-map artifact emitter capability is required"
        )
    selected = emitter
    selected.emit_u64_table(output_path, (
        (f"{prefix}_offset_map_abi", ((OFFSET_MAP_ABI_VERSION,),)),
        (f"{prefix}_forward_entries", (
            (original, translated) for original, translated in forward
        )),
        (f"{prefix}_forward_count", ((len(forward),),)),
        (f"{prefix}_reverse_entries", (
            (translated, original) for translated, original in reverse
        )),
        (f"{prefix}_reverse_count", ((len(reverse),),)),
    ))


def export_json(mapping: dict[int, int], output_path: str | Path) -> None:
    entries = [
        {
            "original": original,
            "original_hex": hex(original),
            "translated": translated,
            "translated_hex": hex(translated),
        }
        for original, translated in sorted(mapping.items())
    ]
    document = {
        "format": "chimera-offset-map-v1",
        "entries": entries,
    }
    Path(output_path).write_text(
        json.dumps(document, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _safe_symbol(name: str) -> str:
    return "".join(character if character.isalnum() else "_" for character in name)
