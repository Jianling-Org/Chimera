from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from chimera.preprocess.offline.analysis.offsetmap import OFFSET_MAP_ABI_VERSION
from chimera.preprocess.offline.analysis.offsetmap.codegen import (
    export_asm,
    parse_asm_source,
    parse_translated_dump,
)
from chimera.preprocess.offline.analysis.arch.riscv.rvv import RvvArtifactEmitter
from chimera.preprocess.offline.analysis.toolchain.objdump import LinuxObjdump
from chimera.preprocess.offline.analysis.toolchain.translator import ExternalTranslator


class OffsetMapArtifactTests(unittest.TestCase):
    def test_offset_map_parser_accepts_translator_emitted_dollar_symbols(self) -> None:
        symbols = {
            "_ZN3$_08__invokeEPK17riscv_subset_list": 0x2BD6A,
            "_ZN3$_18__invokeEPK17riscv_subset_list": 0x2BDAE,
            "_ZN3$_28__invokeEPK17riscv_subset_list": 0x2BDE4,
            "_ZZN29cpp_auto_suppress_diagnosticsC1EP10cpp_readerEN3$_08__invokeES1_20cpp_diagnostic_level18cpp_warning_reasonP13rich_locationPKcPPv": 0x6ECEA,
        }
        symbols[".leading_component"] = 0x70010
        symbols["$leading_component"] = 0x70020
        translator_format = ExternalTranslator(python="python").format
        disassembly_format = LinuxObjdump("objdump").parse_format

        with tempfile.TemporaryDirectory() as temporary:
            assembly = Path(temporary) / "translated.S"
            dump = Path(temporary) / "translated.dump"
            assembly.write_text(
                "\n".join(
                    line
                    for symbol, address in symbols.items()
                    for line in (
                        f"{symbol}_translated:",
                        f"branch_j_target_{address:x}:",
                    )
                ) + "\nordinary_translated: # entry comment\n"
                "branch_j_target_70000:\n"
                "bad+name_translated:\nbranch_j_target_70030:\n"
                "bad'quoted_translated:\nbranch_j_target_70040:\n"
                "bad:colon_translated:\nbranch_j_target_70050:\n",
                encoding="utf-8",
            )
            labels = parse_asm_source(assembly, translator_format)

            # GNU objdump may print the entry symbol at the address shared with
            # branch_j_target instead of printing the target alias.
            dump.write_text(
                "\n".join(
                    f"{translated:x} <{symbol}_translated>:"
                    for index, (symbol, _) in enumerate(
                        list(symbols.items())[:4]
                    )
                    for translated in (0x1000 + index * 0x20,)
                ) + "\n2000 <branch_j_target_70000>:\n",
                encoding="utf-8",
            )
            mapping = parse_translated_dump(
                dump, labels, translator_format, disassembly_format
            )

        expected_labels = {
            f"{symbol}_translated": address
            for symbol, address in symbols.items()
        }
        expected_labels["ordinary_translated"] = 0x70000
        self.assertEqual(expected_labels, labels)
        self.assertEqual(
            {
                original: 0x1000 + index * 0x20
                for index, original in enumerate(list(symbols.values())[:4])
            }
            | {0x70000: 0x2000},
            mapping,
        )

    def test_export_asm_requires_an_explicit_emitter(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "main.maps.S"
            with self.assertRaisesRegex(RuntimeError, "artifact emitter"):
                export_asm({0x30: 0x10}, output, "main")

    def test_offset_map_assembly_uses_capability_specific_abi_symbol(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "main.maps.S"

            export_asm(
                {0x30: 0x10}, output, "main_vlen1024_to_vlen256",
                emitter=RvvArtifactEmitter(),
            )

            text = output.read_text(encoding="utf-8")
        self.assertEqual(OFFSET_MAP_ABI_VERSION, 1)
        self.assertIn(
            "chimera_main_vlen1024_to_vlen256_offset_map_abi", text
        )
        self.assertNotIn("metadata_abi", text)


if __name__ == "__main__":
    unittest.main()
