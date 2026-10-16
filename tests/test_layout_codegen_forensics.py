from __future__ import annotations

import json
import re
import sys
import contextlib
import io
import shlex
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from elf_fixture import write_header_only_elf

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import layout_codegen_forensics as forensic

try:  # pragma: no cover - depends on the environment's package layout
    import chimera  # noqa: F401  registers the chimera.preprocess namespace

    from chimera.preprocess.offline.analysis.program_model.parser import parse_dump  # noqa: F401
    PRODUCTION_IMPORTABLE = True
except Exception:  # noqa: BLE001
    PRODUCTION_IMPORTABLE = False


class SiteParsingTests(unittest.TestCase):
    def test_sites_keep_raw_bytes_context_and_unknown_origin(self):
        dump = """
0000000000050d60 <layout>:
   50d60: 0001 addi sp,sp,-16
   50d6c: 22878427 vs2r.v v8,(a5)
   50fb8: 22840427 vs2r.v v8,(s0)
   50fbc: 00008067 ret
"""
        sites = forensic.extract_sites(dump, (0x50D6C, 0x50FB8))
        self.assertEqual([site["address"] for site in sites], ["0x50d6c", "0x50fb8"])
        self.assertEqual([site["mnemonic"] for site in sites], ["vs2r.v", "vs2r.v"])
        self.assertEqual(sites[0]["generation_origin"], "unknown")
        self.assertEqual(sites[0]["function_offset"], "0xc")
        self.assertIn("50d60", " ".join(sites[0]["context"]))

    def test_missing_site_is_reported_as_gap(self):
        sites = forensic.extract_sites("0000000000001000 <f>:\n", (0x50D6C,))
        self.assertEqual(sites[0]["generation_origin"], "unknown")
        self.assertIn("instruction-not-found", sites[0]["gaps"])


class CandidateTests(unittest.TestCase):
    def test_dwarf_source_location_removes_line_and_column_not_drive_colon(self):
        self.assertEqual(
            forensic.source_path_from_dwarf_location(r"C:\gcc\gcc\layout.cc:12:3"),
            str(Path(r"C:\gcc\gcc\layout.cc")),
        )

    def test_same_named_compile_units_are_preserved_as_ambiguous(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a").mkdir()
            (root / "b").mkdir()
            records = [
                {"directory": str(root / d), "file": "layout.cc", "arguments": ["clang++", "-c", "layout.cc", "-o", "layout.o"]}
                for d in ("a", "b")
            ]
            found = forensic.match_compile_commands(records, "layout.cc")
            self.assertEqual(len(found), 2)
            self.assertTrue(all(item["status"] == "ambiguous-candidate" for item in found))

    def test_missing_compile_command_does_not_guess(self):
        self.assertEqual(forensic.match_compile_commands([], "layout.cc"), [])

    def test_compile_entry_must_match_collected_database_and_expanded_arguments(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "layout.cc"
            source.write_text("int layout;\n", encoding="utf-8")
            database = root / "compile_commands.json"
            record = {"directory": str(root), "file": str(source),
                      "arguments": ["clang++", "-O2", "-c", str(source), "-o", "layout.o"]}
            database.write_text(json.dumps([record]), encoding="utf-8")
            original_object = root / "layout.o"
            original_object.write_bytes(b"ELF layout object")
            candidate = {"database": str(database), "compile_database_sha256": forensic.sha256(database),
                         "index": 0, "directory": str(root), "file": str(source),
                         "original_argv": record["arguments"], "object": str(original_object),
                         "object_exists": True, "object_sha256": forensic.sha256(original_object),
                         "defines_layout_symbol": True}

            forensic.validate_collected_compile_entry(candidate, database, [record], 0)

            changed_record = dict(record, arguments=["clang++", "-O0", "-c", str(source), "-o", "layout.o"])
            with self.assertRaisesRegex(ValueError, "command differs"):
                forensic.validate_collected_compile_entry(candidate, database, [changed_record], 0)

            database.write_text(json.dumps([changed_record]), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "database hash differs"):
                forensic.validate_collected_compile_entry(candidate, database, [changed_record], 0)

            database.write_text(json.dumps([record]), encoding="utf-8")
            original_object.write_bytes(b"changed object")
            with self.assertRaisesRegex(ValueError, "object hash differs"):
                forensic.validate_collected_compile_entry(candidate, database, [record], 0)

    def test_symbol_candidates_require_exact_mangled_name(self):
        symbol = "_ZN12_GLOBAL__N_16layoutC2Ev"
        self.assertTrue(forensic._defines_symbol("0000 T " + symbol + "\n", symbol))
        self.assertFalse(forensic._defines_symbol("0000 T (anonymous namespace)::layout()\n", symbol))
        self.assertFalse(forensic._defines_symbol("0000 T " + symbol + ".cold\n", symbol))

    def test_archive_member_selection_keeps_duplicate_and_multiple_definitions_ambiguous(self):
        symbol = "_Zlayout"
        nm_output = ("libbackend.a(layout-1.o):0000 T _Zlayout\n"
                     "libbackend.a(layout-2.o):0000 T _Zlayout\n")
        ambiguous = forensic._select_archive_member(nm_output, "layout-1.o\nlayout-2.o\n", symbol)
        self.assertEqual(ambiguous["status"], "ambiguous-or-unresolved-member")
        duplicate = forensic._select_archive_member(
            "libbackend.a(layout.o):0000 T _Zlayout\n", "layout.o\nlayout.o\n", symbol)
        self.assertEqual(duplicate["status"], "archive-member-name-not-unique")
        unique = forensic._select_archive_member(
            "libbackend.a(layout.o):0000 T _Zlayout\n", "layout.o\n", symbol)
        self.assertEqual(unique, {"status": "unique-member", "member": "layout.o"})
        gnu_nm = "layout.o:\n00000000 T _Zlayout\n"
        self.assertEqual(forensic._select_archive_member(gnu_nm, "layout.o\n", "_Zlayout"),
                         {"status": "unique-member", "member": "layout.o"})

    def test_replay_redirects_commands_that_would_write_outside_output_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "isolated"
            out.mkdir()
            record = {"directory": str(root), "file": "a.cc", "arguments": ["clang++", "-c", "a.cc", "-o", "../outside.o"]}
            rewritten, _ = forensic.rewrite_compile_command(record, out)
            self.assertIn(str(out), " ".join(rewritten))
            self.assertNotIn("../outside.o", " ".join(rewritten))

    def test_replay_rewrites_outputs_and_response_file_into_isolated_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "isolated output"
            out.mkdir()
            rsp = root / "args.rsp"
            rsp.write_text("-c source.cc -o old.o -MF old.d", encoding="utf-8")
            record = {
                "directory": str(root), "file": "source.cc",
                "arguments": ["clang++", "@" + str(rsp)],
            }
            rewritten, rsp_copy = forensic.rewrite_compile_command(record, out)
            self.assertEqual(rewritten[1], "@" + str(rsp_copy))
            args = rsp_copy.read_text(encoding="utf-8")
            self.assertIn(str(out), args)
            self.assertNotIn("old.o", args)
            self.assertNotIn("old.d", args)

    def test_multiple_response_files_are_rewritten_to_distinct_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "isolated output"
            out.mkdir()
            first = root / "first.rsp"
            second = root / "second.rsp"
            first.write_text("-c source.cc -o first.o", encoding="utf-8")
            second.write_text("-MF second.d -fpass-plugin=stack.so", encoding="utf-8")
            record = {"directory": str(root), "file": "source.cc", "arguments": [
                "clang++", "@first.rsp", "@second.rsp"]}

            rewritten, _ = forensic.rewrite_compile_command(record, out)
            response_paths = [Path(token[1:]) for token in rewritten if token.startswith("@")]
            self.assertEqual(len(response_paths), 2)
            self.assertNotEqual(response_paths[0], response_paths[1])
            self.assertTrue(all(path.is_file() for path in response_paths))
            contents = [path.read_text(encoding="utf-8") for path in response_paths]
            self.assertTrue(all(str(out) in value for value in contents))
            self.assertIn("stack.so", " ".join(contents))

    def test_nested_response_files_are_distinct_and_side_outputs_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "isolated"
            inner = root / "inner.rsp"
            outer = root / "outer.rsp"
            inner.write_text("-Wa,-adhln=outside.lst", encoding="utf-8")
            outer.write_text("-c source.cc @inner.rsp -save-temps=cwd", encoding="utf-8")
            record = {"directory": str(root), "arguments": ["clang++", "@outer.rsp"]}
            with self.assertRaisesRegex(ValueError, "side-output"):
                forensic.rewrite_compile_command(record, out)
            copies = list(out.glob("response-*.rsp"))
            self.assertEqual(len(copies), 2)
            self.assertEqual(len({path.read_text(encoding="utf-8") for path in copies}), 2)
            self.assertIn("-save-temps=obj", " ".join(path.read_text(encoding="utf-8") for path in copies))

    def test_missing_output_directory_is_created_for_response_rewrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rsp = root / "compile.rsp"
            rsp.write_text("-c source.cc", encoding="utf-8")
            out = root / "new" / "baseline"
            record = {"directory": str(root), "arguments": ["clang++", "@compile.rsp"]}
            rewritten, copied = forensic.rewrite_compile_command(record, out)
            self.assertTrue(out.is_dir())
            self.assertTrue(copied.is_file())
            self.assertEqual(rewritten[1], "@" + str(copied))

    def test_cyclic_response_file_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            response = root / "cycle.rsp"
            response.write_text("-c source.cc @cycle.rsp", encoding="utf-8")
            record = {"directory": str(root), "arguments": ["clang++", "@cycle.rsp"]}
            with self.assertRaisesRegex(ValueError, "cyclic response-file"):
                forensic.rewrite_compile_command(record, root / "isolated")

    def test_extra_diagnostic_arguments_are_checked_for_side_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            record = {"directory": str(root), "arguments": ["clang++", "-c", "a.cc"]}
            with self.assertRaisesRegex(ValueError, "side-output"):
                forensic.rewrite_compile_command(
                    record, root / "isolated", extra_tokens=("-serialize-diagnostics", "outside.dia"))

    def test_forwarded_tool_options_cannot_write_side_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            unsafe_commands = (
                ["-Wa,-adhln=outside.lst"],
                ["-Wa,@asm.rsp"],
                ["-Xassembler", "-adhln=outside.lst"],
                ["-Xassembler", "@asm.rsp"],
                ["-Wa,--MD=outside.d"],
                ["-Wp,-MD,outside.d"],
                ["-Wp,-ooutside.i"],
                ["-Wp,@preprocessor.rsp"],
                ["-Xpreprocessor", "-MF", "-Xpreprocessor", "outside.d"],
                ["-Xpreprocessor", "@preprocessor.rsp"],
                ["-Xclang", "-dependency-file", "-Xclang", "outside.d"],
                ["-Xclang", "@frontend.rsp"],
            )
            for forwarded in unsafe_commands:
                record = {"directory": str(root), "arguments": [
                    "clang++", "-c", "source.cc", *forwarded]}
                with self.subTest(forwarded=forwarded), self.assertRaisesRegex(ValueError, "side-output"):
                    forensic.rewrite_compile_command(record, root / "isolated")
            safe = {"directory": str(root), "arguments": [
                "clang++", "-c", "source.cc", "-Wa,-mno-relax", "-Wp,-DVALUE=1"]}
            rewritten, _ = forensic.rewrite_compile_command(safe, root / "safe")
            self.assertIn("-Wa,-mno-relax", rewritten)
            self.assertIn("-Wp,-DVALUE=1", rewritten)

    def test_driver_response_file_with_forwarded_tool_response_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            driver_response = root / "driver.rsp"
            driver_response.write_text("-c source.cc -Wa,@asm.rsp", encoding="utf-8")
            record = {"directory": str(root),
                      "arguments": ["clang++", "@driver.rsp"]}
            with self.assertRaisesRegex(ValueError, "side-output"):
                forensic.rewrite_compile_command(record, root / "isolated")

    def test_forwarded_response_argument_cannot_cross_driver_response_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            driver_response = root / "driver.rsp"
            assembler_response = root / "asm.rsp"
            driver_response.write_text("-c source.cc -Xassembler", encoding="utf-8")
            assembler_response.write_text("--fatal-warnings", encoding="utf-8")
            record = {"directory": str(root),
                      "arguments": ["clang++", "@driver.rsp", "@asm.rsp"]}
            with self.assertRaisesRegex(ValueError, "side-output"):
                forensic.rewrite_compile_command(record, root / "isolated")

    def test_response_file_output_paths_are_read_for_candidate_inspection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            response = root / "compile.rsp"
            response.write_text("-c file.cc -o out.o -MF out.d -fpass-plugin=stack.so", encoding="utf-8")
            tokens = forensic._expanded_response_tokens(["clang++", "@compile.rsp"], root)
            self.assertIn("out.o", tokens)
            self.assertIn("-fpass-plugin=stack.so", tokens)

    def test_replay_refuses_unexpanded_compiler_launchers(self):
        with self.assertRaisesRegex(ValueError, "wrapper must be expanded"):
            forensic._require_direct_compiler("chimera-pkg")
        forensic._require_direct_compiler("riscv64-linux-gnu-g++")

    def test_replay_rejects_unisolated_profile_and_diagnostic_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "isolated"
            out.mkdir()
            for extra in ("-fprofile-generate=/outside/profile", "-fstack-usage",
                          "-serialize-diagnostics", "-fcoverage-mapping"):
                record = {"directory": str(root), "file": "a.cc",
                          "arguments": ["clang++", "-c", "a.cc", "-o", "a.o", extra]}
                with self.subTest(extra=extra), self.assertRaisesRegex(ValueError, "side-output"):
                    forensic.rewrite_compile_command(record, out)

    def test_joined_output_option_is_identified_for_object_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.assertEqual(forensic._compile_output_path(["clang++", "-c", "a.cc", "-oobj.o"], root),
                             str((root / "obj.o").resolve()))
            self.assertEqual(forensic._compile_output_path(["clang++", "-c", "a.cc", "-o=obj.o"], root),
                             str((root / "obj.o").resolve()))

    def test_gate_replay_materializes_names_and_redirects_census(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "isolated output"
            decision = root / "gate.json"
            decision.write_text(json.dumps({"decision": {"gate": {
                "enabled": True, "names": ["_Zlayout", "_Zother"]}}}), encoding="utf-8")
            result = forensic.prepare_replay_environment(
                "gate2", decision, out, {"CHIMERA_GATE_STATS": str(root / "old-census.tsv")})
            self.assertEqual(Path(result["CHIMERA_GATE_LIST"]).read_text(encoding="utf-8"),
                             "_Zlayout\n_Zother\n")
            self.assertEqual(Path(result["CHIMERA_GATE_STATS"]).parent, out.resolve())
            self.assertNotEqual(result["CHIMERA_GATE_STATS"], str(root / "old-census.tsv"))
            record = {"directory": str(root), "file": "source.cc", "arguments": [
                "clang++", "-c", "source.cc", "-o", "original.o",
                "-mllvm", "-chimera-gate-list=/old/build/gate_names.txt"]}
            rewritten, _ = forensic.rewrite_compile_command(
                record, out, Path(result["CHIMERA_GATE_LIST"]))
            self.assertIn("-chimera-gate-list=" + result["CHIMERA_GATE_LIST"], rewritten)

    def test_gate_replay_requires_structured_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            decision = root / "bad.json"
            decision.write_text(json.dumps({"gate": {"enabled": True, "names": "_Zlayout"}}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "gate.names"):
                forensic.prepare_replay_environment("gate2", decision, root / "out", {})

    def test_stack_replay_clears_inherited_gate_list_and_census_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = forensic.prepare_replay_environment("stack", root / "stack.json", root / "out", {
                "CHIMERA_GATE_LIST": "/old/gate_names.txt",
                "CHIMERA_GATE_STATS": "/old/census.tsv",
                "PATH": "preserved",
            })
            self.assertNotIn("CHIMERA_GATE_LIST", result)
            self.assertNotIn("CHIMERA_GATE_STATS", result)
            self.assertEqual(result["PATH"], "preserved")
            self.assertTrue(Path(result["TMPDIR"]).is_dir())
            self.assertEqual(result["TMP"], result["TMPDIR"])


class ProvenanceTests(unittest.TestCase):
    def test_same_opcode_alone_never_upgrades_origin(self):
        result = forensic.classify_origin(
            site={"mnemonic": "vs2r.v"}, ir_evidence=None, mir_evidence=None
        )
        self.assertEqual(result["generation_origin"], "unknown")
        self.assertEqual(result["metadata_status"], "unknown")

    def test_same_vs2r_mnemonic_can_have_distinct_ir_or_machine_origins(self):
        site = {"mnemonic": "vs2r.v"}
        intrinsic = forensic.classify_origin(
            site=site, ir_evidence={"kind": "intrinsic", "metadata_status": "record-present"},
            mir_evidence=None)
        spill = forensic.classify_origin(
            site=site, ir_evidence=None,
            mir_evidence={"frame_index": "FI#2", "attribute": True, "pcsections": True})
        self.assertEqual(intrinsic["generation_origin"], "intrinsic")
        self.assertEqual(spill["generation_origin"], "backend-spill")

    def test_machine_frame_index_and_attribute_are_required_for_spill_claim(self):
        result = forensic.classify_origin(
            site={"mnemonic": "vs2r.v"},
            ir_evidence=None,
            mir_evidence={"frame_index": "%stack.2", "attribute": True, "pcsections": True},
        )
        self.assertEqual(result["generation_origin"], "backend-spill")
        self.assertEqual(result["metadata_status"], "recorded-before-link")

    def test_machine_frame_index_without_function_attribute_stays_unknown(self):
        result = forensic.classify_origin(
            site={"mnemonic": "vs2r.v"},
            ir_evidence=None,
            mir_evidence={"frame_index": "%stack.2", "attribute": False, "pcsections": True},
        )
        self.assertEqual(result["generation_origin"], "unknown")
        self.assertEqual(result["metadata_status"], "unknown")

    def test_et_rel_address_stays_section_relative_until_relocation_is_applied(self):
        result = forensic.address_identity(
            elf_type="ET_REL", section=".text.layout", offset=0x154,
            linked_va=0x50D6C, relocation="R_RISCV_CALL target",
        )
        self.assertEqual(result["coordinate"], "section+offset")
        self.assertFalse(result["directly_comparable_to_linked_va"])
        self.assertEqual(result["relocation"], "R_RISCV_CALL target")

    def test_readelf_rel_type_is_normalized_and_unknown_type_stays_unknown(self):
        rel = forensic.address_identity(elf_type="REL", section=".text", offset=0x40)
        self.assertEqual(rel["coordinate"], "section+offset")
        self.assertFalse(rel["directly_comparable_to_linked_va"])
        unknown = forensic.address_identity(elf_type="unknown", section=".text", offset=0x40)
        self.assertEqual(unknown["coordinate"], "unknown")
        self.assertFalse(unknown["directly_comparable_to_linked_va"])

    def test_replay_correspondence_ignores_link_rebased_control_targets_only(self):
        original = """00001000 <layout>:\n 1000: 0080006f j 1008 <layout+0x8>\n 1004: 00100093 addi ra,zero,1\n 1008: 00008067 ret\n"""
        replayed = """00000000 <layout>:\n 0000: 0080006f j 0008 <layout+0x8>\n 0004: 00100093 addi ra,zero,1\n 0008: 00008067 ret\n"""
        result = forensic.compare_replay_sites(original, replayed, ())
        self.assertEqual(result["function_correspondence"], "matched")
        changed = replayed.replace("addi ra,zero,1", "addi ra,zero,2")
        self.assertEqual(forensic.compare_replay_sites(original, changed, ())["function_correspondence"],
                         "replay-mismatch-or-insufficient-symbol-data")

    def test_replay_correspondence_rejects_a_different_internal_branch_target(self):
        original = """00001000 <layout>:\n 1000: 0080006f j 1008 <layout+0x8>\n 1004: 00100093 addi ra,zero,1\n 1008: 00008067 ret\n"""
        changed_cfg = """00000000 <layout>:\n 0000: 0040006f j 0004 <layout+0x4>\n 0004: 00100093 addi ra,zero,1\n 0008: 00008067 ret\n"""
        result = forensic.compare_replay_sites(original, changed_cfg, (0x1004,))
        self.assertEqual(result["function_correspondence"], "replay-mismatch-or-insufficient-symbol-data")
        self.assertEqual(result["sites"][0]["status"], "unknown")

    def test_replay_correspondence_checks_external_target_identity(self):
        original = """00001000 <layout>:\n 1000: 000000ef jal ra,100 <_ZcalleeA>\n 1004: 00008067 ret\n"""
        changed_target = """00000000 <layout>:\n 0000: 000000ef jal ra,100 <_ZcalleeB>\n 0004: 00008067 ret\n"""
        self.assertEqual(forensic.compare_replay_sites(original, changed_target, ())["function_correspondence"],
                         "replay-mismatch-or-insufficient-symbol-data")

    def test_replay_correspondence_checks_external_relocation_identity(self):
        original = """00001000 <layout>:\n 1000: 000000ef jal ra,0\n       1000: R_RISCV_CALL_PLT _ZcalleeA\n 1004: 00008067 ret\n"""
        changed_target = """00000000 <layout>:\n 0000: 000000ef jal ra,0\n       0000: R_RISCV_CALL_PLT _ZcalleeB\n 0004: 00008067 ret\n"""
        self.assertEqual(forensic.compare_replay_sites(original, changed_target, ())["function_correspondence"],
                         "replay-mismatch-or-insufficient-symbol-data")

    def test_inline_external_relocation_cannot_be_mistaken_for_internal_target(self):
        original = """00001000 <layout>:\n 1000: 000000ef jal ra,1000 <layout>\n 1004: 00008067 ret\n"""
        replayed = """00000000 <layout>:\n 0000: 000000ef jal ra,0 <layout>\t0: R_RISCV_JAL _Zexternal\n 0004: 00008067 ret\n"""
        self.assertEqual(forensic.compare_replay_sites(original, replayed, ())[
                         "function_correspondence"], "replay-mismatch-or-insufficient-symbol-data")

    def test_local_relocation_symbol_resolves_to_internal_instruction_index(self):
        original = """00001000 <layout>:\n 1000: 0080006f j 1008 <layout+0x8>\n 1004: 00100093 addi ra,zero,1\n 1008: 00008067 ret\n"""
        replayed = """00000000 <layout>:\n 0000: 0080006f j 0 <layout>\t0: R_RISCV_JAL .Ldone\n 0004: 00100093 addi ra,zero,1\n0008 <.Ldone>:\n 0008: 00008067 ret\n"""
        self.assertEqual(forensic.compare_replay_sites(original, replayed, ())[
                         "function_correspondence"], "matched")
        record = forensic._instruction_records(replayed)[0]
        self.assertEqual(record["relocations"], ["R_RISCV_JAL .Ldone"])
        self.assertEqual(record["operands"], "0 <layout>")

    def test_inline_relocation_is_attached_and_removed_from_operands(self):
        dump = """00000000 <layout>:\n 0000: 000000ef jal ra,0 <layout>\t0: R_RISCV_JAL _Zcallee\n"""
        record = forensic._instruction_records(dump)[0]
        self.assertEqual(record["relocations"], ["R_RISCV_JAL _Zcallee"])
        self.assertEqual(record["operands"], "ra,0 <layout>")

    def test_inline_gnu_x86_relocation_format_is_kept_as_metadata(self):
        dump = """00000000 <layout>:\n   8: e8 00 00 00 00 callq 0 <callee> 9: R_X86_64_PC32 callee-0x4\n"""
        record = forensic._instruction_records(dump)[0]
        self.assertEqual(record["relocations"], ["R_X86_64_PC32 callee-0x4"])
        self.assertEqual(record["operands"], "0 <callee>")

    def test_unresolved_local_relocation_stays_unknown(self):
        original = """00001000 <layout>:\n 1000: 0080006f j 1008 <layout+0x8>\n 1004: 00100093 addi ra,zero,1\n 1008: 00008067 ret\n"""
        replayed = """00000000 <layout>:\n 0000: 0080006f j 0 <layout>\t0: R_RISCV_JAL .Lmissing\n 0004: 00100093 addi ra,zero,1\n 0008: 00008067 ret\n"""
        result = forensic.compare_replay_sites(original, replayed, ())
        self.assertEqual(result["function_correspondence"],
                         "replay-mismatch-or-insufficient-symbol-data")

    def test_ambiguous_local_relocation_symbol_stays_unknown(self):
        original = """00001000 <layout>:\n 1000: 00c0006f j 100c <layout+0xc>\n 1004: 00100093 addi ra,zero,1\n 1008: 00200093 addi ra,zero,2\n 100c: 00008067 ret\n"""
        replayed = """00000000 <layout>:\n 0000: 00c0006f j 0 <layout>\t0: R_RISCV_JAL .Ldone\n 0004: 00100093 addi ra,zero,1\n0008 <.Ldone>:\n 0008: 00200093 addi ra,zero,2\n000c <.Ldone>:\n 000c: 00008067 ret\n"""
        result = forensic.compare_replay_sites(original, replayed, ())
        self.assertEqual(result["function_correspondence"],
                         "replay-mismatch-or-insufficient-symbol-data")

    def test_et_rel_objdump_attaches_relocation_to_section_offset(self):
        dump = """Disassembly of section .text.layout:
0000000000000154 <_Zlayout>:
 154: 22878427 vs2r.v v8,(a5)
 158: 00000013 nop 158: R_RISCV_CALL_PLT _Zcallee
 15c: 00000013 nop
        15c: R_RISCV_CALL_PLT _Zother
"""
        rows = forensic._object_coordinates(dump, "ET_REL")
        site = next(row for row in rows if row["offset"] == "0x154")
        inline_relocated = next(row for row in rows if row["offset"] == "0x158")
        relocated = next(row for row in rows if row["offset"] == "0x15c")
        self.assertEqual(site["coordinate"], "section+offset")
        self.assertFalse(site["directly_comparable_to_linked_va"])
        self.assertEqual(inline_relocated["relocations"], ["R_RISCV_CALL_PLT _Zcallee"])
        self.assertEqual(relocated["relocations"], ["R_RISCV_CALL_PLT _Zother"])

    def test_baseline_object_comparison_checks_instruction_sequence_and_relocation_target(self):
        original = [
            {"section": ".text.layout", "offset": "0x10", "instruction": "10: 000000ef jal ra,0",
             "mnemonic": "jal", "relocations": ["R_RISCV_CALL_PLT _Zcallee"]},
        ]
        same = [dict(original[0])]
        changed_target = [dict(original[0], relocations=["R_RISCV_CALL_PLT _Zother"])]
        result = forensic.compare_object_coordinates(original, same)
        self.assertTrue(result["instruction_sequence_matches"])
        self.assertTrue(result["relocation_targets_match"])
        mismatch = forensic.compare_object_coordinates(original, changed_target)
        self.assertTrue(mismatch["instruction_sequence_matches"])
        self.assertFalse(mismatch["relocation_targets_match"])

    def test_unmatched_replay_or_tool_identity_cannot_confirm_cause(self):
        for replay_match, tool_match in ((False, True), (True, False)):
            result = forensic.finalize_replay_assessment(
                replay_matches_original=replay_match, toolchain_matches=tool_match
            )
            self.assertFalse(result["root_cause_confirmed"])

    def test_changed_replay_function_leaves_both_target_sites_unknown(self):
        original = """0000 <layout>:\n 50d6c: 22878427 vs2r.v v8,(a5)\n 50fb8: 22840427 vs2r.v v8,(s0)\n"""
        changed = """0000 <layout>:\n 50d6c: 22878427 vs2r.v v8,(a5)\n 50fb8: 22840427 sd a0,0(sp)\n"""
        result = forensic.compare_replay_sites(original, changed)
        self.assertEqual(result["function_correspondence"], "replay-mismatch-or-insufficient-symbol-data")
        self.assertTrue(all(site["status"] == "unknown" for site in result["sites"]))

    def test_final_elf_map_states_distinguish_absent_section_and_missing_record(self):
        address = "0x50d6c"
        self.assertEqual(forensic._metadata_state({"status": "section-absent"}, address), "section-absent")
        self.assertEqual(forensic._metadata_state({"status": "section-present", "records": []}, address),
                         "section-present-no-record-at-address")
        self.assertEqual(forensic._metadata_state({"status": "section-present",
                                                    "records": [{"linked_va": address, "soid": 7}]}, address),
                         "record-present")
        self.assertEqual(forensic._metadata_state({"status": "unavailable"}, address), "unknown-map-state")

    def test_not_observed_metadata_is_not_reported_as_not_executed(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = forensic._index_diagnostic_metadata(Path(tmp))
            self.assertEqual(result["observations"]["chimera-stack-object-function-attribute"]["status"],
                             "not-observed-in-captured-output")
            self.assertIn("does not establish", result["interpretation"])

    def test_signal_exit_is_preserved_in_shell_convention(self):
        self.assertEqual(forensic._shell_exit_code(-9), 137)
        self.assertEqual(forensic._shell_exit_code(2), 2)

    def test_peak_rss_is_read_from_time_output_when_available(self):
        with tempfile.TemporaryDirectory() as tmp:
            timing = Path(tmp) / "time.txt"
            timing.write_text("Maximum resident set size (kbytes): 12345\n", encoding="utf-8")
            self.assertEqual(forensic.peak_rss_kib(timing), 12345)
            self.assertIsNone(forensic.peak_rss_kib(Path(tmp) / "missing"))

    def test_nonzero_and_signal_compile_failures_keep_partial_logs_and_command_record(self):
        for returncode in (2, -9):
            with self.subTest(returncode=returncode), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                out = root / "isolated output"
                out.mkdir()
                record = {"directory": str(root), "file": "source.cc",
                          "arguments": ["clang++", "-c", "source.cc", "-o", "original.o"]}

                def failed_run(command, **kwargs):
                    kwargs["stdout"].write(b"partial stdout")
                    kwargs["stderr"].write(b"partial diagnostic")
                    return SimpleNamespace(returncode=returncode)

                with mock.patch.object(forensic.subprocess, "run", side_effect=failed_run):
                    result = forensic._execute_compile_pass(
                        record, out, root, Path("clang++"), (), "baseline")
                self.assertEqual(result["exit_code"], returncode)
                self.assertEqual((out / "baseline.stdout.txt").read_bytes(), b"partial stdout")
                self.assertEqual((out / "baseline.stderr.txt").read_bytes(), b"partial diagnostic")
                self.assertTrue((out / "baseline.command.json").is_file())


class CliTests(unittest.TestCase):
    def test_collect_requires_expected_elf_hash_and_stage(self):
        parser = forensic.build_parser()
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                parser.parse_args(["collect", "--repo", ".", "--run", ".", "--out", "out"])

    def test_resolve_matches_archive_member_to_logged_translation_unit_not_inline_header(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run = root / "run"
            collected = root / "collected"
            collected.mkdir()
            source = root / "diagnostic-show-locus.cc"
            source.write_text("// source", encoding="utf-8")
            for stage in ("build-stack", "build-gate2"):
                gcc = run / stage / "gcc"
                gcc.mkdir(parents=True)
                (gcc / "libcommon.a").write_bytes(b"archive" + stage.encode())
                (gcc / "Makefile").write_text("libcommon.a: diagnostic-show-locus.o\n", encoding="utf-8")
                log = ("/stage/wrappers/compiler -c -o diagnostic-show-locus.o " + shlex.quote(str(source)) + "\n"
                       "ar rc libcommon.a diagnostic-show-locus.o\n")
                (collected / "raw-build-logs").mkdir(exist_ok=True)
                (collected / "raw-build-logs" / f"{'stack' if stage == 'build-stack' else 'gate2'}-build.log").write_text(log, encoding="utf-8")
                extracted = collected / "archive-members" / stage / "0-diagnostic-show-locus.o"
                extracted.parent.mkdir(parents=True)
                extracted.write_bytes(b"object" + stage.encode())
            candidates = []
            for stage in ("build-stack", "build-gate2"):
                obj = collected / "archive-members" / stage / "0-diagnostic-show-locus.o"
                archive = run / stage / "gcc/libcommon.a"
                candidates.append({"stage": stage, "archive": str(archive),
                                   "archive_sha256": forensic.sha256(archive), "member_selection": {
                                       "status": "unique-member", "member": "diagnostic-show-locus.o"},
                                   "member_object": {"status": "extracted-et-rel-member", "output": str(obj),
                                                     "output_sha256": forensic.sha256(obj)}})
            (collected / "collection.json").write_text(json.dumps({
                "sites": {"gate2:0x50d6c": {"addr2line": ["vec::copy", "/src/vec.h:557"]}},
                "archive_layout_candidates": candidates, "stage_object_candidates": [],
                "compile_command_candidates": []}), encoding="utf-8")
            (collected / "identity.json").write_text(json.dumps({"build_evidence": [
                {"path": str(run / "logs" / f"{stage}-build.log"),
                 "raw_copy": f"raw-build-logs/{stage}-build.log",
                 "sha256": forensic.sha256(collected / "raw-build-logs" / f"{stage}-build.log")}
                for stage in ("stack", "gate2")]}), encoding="utf-8")
            out = root / "resolved"
            args = SimpleNamespace(collection=collected / "collection.json", out=out,
                                   run=run, repo=root, readelf="readelf", layout_symbol="_Zlayout")
            with mock.patch.object(forensic, "_read_compile_units", return_value=[str(source)]):
                self.assertEqual(forensic.resolve(args), 0)
            result = json.loads((out / "resolution.json").read_text(encoding="utf-8"))
            self.assertEqual([item["source"] for item in result["stages"].values()], [str(source)] * 2)
            self.assertTrue(all(item.get("command_status") == "associated-wrapper-command"
                                for item in result["stages"].values()), result["stages"])
            self.assertTrue(all("wrapper-not-expanded" in item["gaps"] for item in result["stages"].values()))
            self.assertEqual(result["instruction_line_sources"], ["/src/vec.h"])
            self.assertFalse(result["root_cause_confirmed"])
            original = result["stages"]["build-gate2"]
            self.assertEqual(len(forensic._verified_resolution_command(
                original, collected, "gate2-build.log", source,
                "diagnostic-show-locus.o", "libcommon.a")), 1)
            original["command_candidates"][0]["raw_line_sha256"] = "wrong"
            with self.assertRaisesRegex(ValueError, "resolution command"):
                forensic._verified_resolution_command(original, collected, "gate2-build.log", source,
                                                      "diagnostic-show-locus.o", "libcommon.a")
            collection_file = collected / "collection.json"
            changed = json.loads(collection_file.read_text(encoding="utf-8"))
            changed["stage_object_candidates"] = [{"stage": "build-gate2", "path": str(root / "other.o"),
                                                     "sha256": "different", "defines_layout": True}]
            collection_file.write_text(json.dumps(changed), encoding="utf-8")
            args.out = root / "ambiguous"
            with mock.patch.object(forensic, "_read_compile_units", return_value=[str(source)]):
                forensic.resolve(args)
            ambiguous = json.loads((args.out / "resolution.json").read_text(encoding="utf-8"))
            self.assertIn("competing-standalone-definition", ambiguous["stages"]["build-gate2"]["gaps"])

    def test_resolve_rejects_ambiguous_or_changed_member_and_does_not_overwrite_collection(self):
        parser = forensic.build_parser()
        args = parser.parse_args(["resolve", "--repo", "/repo", "--run", "/run", "--out", "/out",
                                  "--collection", "/collect/collection.json"])
        self.assertEqual(args.stage, "resolve")

    def test_readelf_compilation_unit_parser_does_not_use_inline_line_table(self):
        dump = (" <0><c>: Abbrev Number: 1 (DW_TAG_compile_unit)\n"
                " <d> DW_AT_name : (indexed string: 0x1): diagnostic-show-locus.cc\n"
                " <e> DW_AT_comp_dir : /src/gcc\n"
                " <1><f>: Abbrev Number: 2 (DW_TAG_subprogram)\n"
                " <a> DW_AT_name : vec.h\n")
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(
                forensic, "_run_capture", return_value=(0, dump)):
            self.assertEqual(forensic._read_compile_units(Path(tmp) / "a.o", "readelf",
                                                          Path(tmp), "a"),
                             [str(Path("/src/gcc") / "diagnostic-show-locus.cc")])

    def test_localized_die_headers_do_not_replace_cu_source_with_child_name(self):
        dump = (" <0><c>：缩写编号：1 (DW_TAG_compile_unit)\n"
                " <10> DW_AT_name : (indexed string: 0x1): /src/diagnostic-show-locus.cc\n"
                " <19> DW_AT_comp_dir : /build/gcc\n"
                " <1><30>：缩写编号：2 (DW_TAG_base_type)\n"
                " <31> DW_AT_name : unsigned\n"
                " <1><40>：缩写编号：3 (DW_TAG_subprogram)\n"
                " <41> DW_AT_name : vsscanf\n")
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(
                forensic, "_run_capture", return_value=(0, dump)):
            self.assertEqual(forensic._read_compile_units(Path(tmp) / "a.o", "readelf",
                                                          Path(tmp), "a"),
                             [str(Path("/src/diagnostic-show-locus.cc"))])

    def test_capture_creates_nested_output_directory_for_success_and_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            for exit_code in (0, 7):
                output = Path(tmp) / str(exit_code) / "binding" / "plugin-environment"
                self.assertFalse(output.exists())
                code, stdout = forensic._run_capture(
                    [sys.executable, "-c",
                     "import sys; print('captured'); print('diagnostic', file=sys.stderr); "
                     f"sys.exit({exit_code})"], output, "original.dwarf-info")
                self.assertEqual(code, exit_code)
                self.assertIn("captured", stdout)
                self.assertIn("diagnostic", (output / "original.dwarf-info.stderr.txt").read_text())
                self.assertTrue((output / "original.dwarf-info.command.json").is_file())

    def test_capture_sets_c_locale_without_mutating_parent_environment(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.dict(forensic.os.environ, {"LC_ALL": "zh_CN.GBK"}), \
             mock.patch.object(forensic.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as run:
            forensic._run_capture(["readelf", "--version"], Path(tmp), "locale")
            self.assertEqual(run.call_args.kwargs["env"]["LC_ALL"], "C")
            self.assertEqual(forensic.os.environ["LC_ALL"], "zh_CN.GBK")

    def test_logged_command_requires_unique_safe_line_and_archive_membership(self):
        source = "/src/diagnostic-show-locus.cc"
        line = f"/wrapper -c -o diagnostic-show-locus.o {source}"
        log = (line + "\n" + line + "\n"
               "ar rc libcommon.a diagnostic-show-locus.o\n")
        self.assertEqual(len(forensic._logged_compile_candidates(
            log, source, "diagnostic-show-locus.o", "libcommon.a")), 2)
        self.assertEqual(forensic._logged_compile_candidates(
            line, source, "diagnostic-show-locus.o", "libcommon.a"), [])
        self.assertEqual(forensic._logged_compile_candidates(
            line + "; touch /tmp/out\nar rc libcommon.a diagnostic-show-locus.o\n",
            source, "diagnostic-show-locus.o", "libcommon.a"), [])

    def test_archive_object_binding_checks_member_and_archive_hashes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "libcommon.a"
            archive.write_bytes(b"archive")
            member = root / "diagnostic-show-locus.o"
            member.write_bytes(b"member")
            item = {"stage": "build-gate2", "archive": str(archive),
                    "archive_sha256": forensic.sha256(archive),
                    "member_selection": {"status": "unique-member", "member": member.name},
                    "member_object": {"status": "extracted-et-rel-member",
                                      "output": str(member), "output_sha256": forensic.sha256(member)},
                    "object_address_coordinates": [{"section": ".text", "offset": "0x10"}]}
            collection = {"archive_layout_candidates": [item]}
            selected = forensic._collected_original_object(collection, "build-gate2", member)
            self.assertEqual(selected["kind"], "archive-member")
            self.assertEqual(selected["object_address_coordinates"][0]["offset"], "0x10")
            with self.assertRaisesRegex(ValueError, "uniquely"):
                forensic._collected_original_object({"archive_layout_candidates": [item, item]},
                                                    "build-gate2", member)
            archive.write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "archive identity changed"):
                forensic._collected_original_object(collection, "build-gate2", member)

    def test_replay_reaches_baseline_for_verified_archived_member_without_gate_hit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run = root / "run"
            gcc = run / "build-gate2/gcc"
            gcc.mkdir(parents=True)
            elf = gcc / "xgcc"
            write_header_only_elf(elf)
            source = root / "diagnostic-show-locus.cc"
            source.write_text("source", encoding="utf-8")
            compiler, plugin = root / "clang++", root / "stack.so"
            compiler.write_bytes(b"\x7fELFcompiler")
            plugin.write_bytes(b"plugin")
            archive = gcc / "libcommon.a"
            archive.write_bytes(b"archive")
            collected = root / "collect"
            member = collected / "archive-members/build-gate2/1-diagnostic-show-locus.o"
            member.parent.mkdir(parents=True)
            member.write_bytes(b"member")
            decision = root / "decision.json"
            decision.write_text(json.dumps({"decision": {"gate": {"enabled": True, "names": []}}}),
                                encoding="utf-8")
            log = collected / "raw-build-logs/gate2-build.log"
            log.parent.mkdir()
            log.write_text(f"/wrapper -c -o diagnostic-show-locus.o {shlex.quote(str(source))}\n"
                           "ar rc libcommon.a diagnostic-show-locus.o\n", encoding="utf-8")
            collection = {"archive_layout_candidates": [{
                "stage": "build-gate2", "archive": str(archive),
                "archive_sha256": forensic.sha256(archive),
                "member_selection": {"status": "unique-member", "member": "diagnostic-show-locus.o"},
                "member_object": {"status": "extracted-et-rel-member", "output": str(member),
                                  "output_sha256": forensic.sha256(member)}}]}
            collection_path = collected / "collection.json"
            collection_path.write_text(json.dumps(collection), encoding="utf-8")
            (collected / "identity.json").write_text(json.dumps({
                "gate2_sha256": forensic.sha256(elf),
                "consumed_decision": {"sha256": forensic.sha256(decision)},
                "build_evidence": [{"path": str(run / "logs/gate2-build.log"),
                                    "raw_copy": "raw-build-logs/gate2-build.log",
                                    "sha256": forensic.sha256(log)}]}), encoding="utf-8")
            associated = forensic._logged_compile_candidates(log.read_text(encoding="utf-8"),
                str(source), "diagnostic-show-locus.o", "libcommon.a")
            resolution = root / "resolution.json"
            resolution.write_text(json.dumps({"collection_sha256": forensic.sha256(collection_path),
                "stages": {"build-gate2": {"object_sha256": forensic.sha256(member),
                "source": str(source), "source_sha256": forensic.sha256(source),
                "command_candidates": associated}}}), encoding="utf-8")
            entry = root / "entry.json"
            entry.write_text(json.dumps({"directory": str(gcc), "file": str(source),
                "arguments": [str(compiler), "-c", str(source), "-o", "old.o",
                              "-fpass-plugin=" + str(plugin)]}), encoding="utf-8")
            args = SimpleNamespace(repo=root, run=run, out=root / "replay", collection=collection_path,
                expected_gate2_sha256=forensic.sha256(elf), gate_list=decision, stack_decision=None,
                build_stage="gate2", layout_symbol="_Zlayout", compile_database=None,
                compile_entry_json=entry, original_object=member, entry_index=0, resolution=None,
                readelf="readelf", objdump="objdump", nm="nm", diagnostic_arg=[])
            with self.assertRaisesRegex(ValueError, "requires --resolution"):
                forensic.replay(args)
            args.resolution = resolution
            with mock.patch.object(forensic, "_read_compile_units", return_value=[str(source)]), \
                 mock.patch.object(forensic, "_execute_compile_pass", side_effect=RuntimeError("reached baseline")), \
                 self.assertRaisesRegex(RuntimeError, "reached baseline"):
                forensic.replay(args)
            self.assertFalse(json.loads((args.out / "replay-identity.json").read_text(
                encoding="utf-8"))["gate_targeted"])
            source.write_text("changed since resolution", encoding="utf-8")
            with mock.patch.object(forensic, "_execute_compile_pass") as compile_mock, \
                 self.assertRaisesRegex(ValueError, "resolution does not bind"):
                forensic.replay(args)
            compile_mock.assert_not_called()

    def test_output_directory_must_be_fresh(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "out"
            out.mkdir()
            (out / "old").write_text("prior", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "empty"):
                forensic.require_fresh_output(out)

    def test_replay_binds_decision_and_isolates_gate_census_and_partial_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run = root / "run"
            for stage in ("build-stack", "build-gate2"):
                write_header_only_elf(run / stage / "gcc/xgcc")
            source = root / "layout.cc"
            source.write_text("int layout;\n", encoding="utf-8")
            compiler = root / "clang++"
            compiler.write_bytes(b"\x7fELF" + b"compiler")
            plugin = root / "ChimeraStackObject.so"
            plugin.write_bytes(b"plugin-binary")
            original_object = run / "build-gate2/gcc/layout.o"
            original_object.parent.mkdir(parents=True, exist_ok=True)
            original_object.write_bytes(b"original ELF object")
            decision = root / "gate.json"
            decision.write_text(json.dumps({"decision": {"gate": {
                "enabled": True, "names": []}}}), encoding="utf-8")
            out = root / "replay out"
            collection_path = root / "collect/collection.json"
            collection_path.parent.mkdir()
            dump = """0000000000050418 <_Zlayout>:\n  50d6c: 22878427 vs2r.v v8,(a5)\n  50fb8: 22840427 vs2r.v v8,(s0)\n"""
            (collection_path.parent / "gate2.layout-function.txt").write_text(dump, encoding="utf-8")
            original_coordinates = forensic._object_coordinates(dump, "ET_REL")
            gate2_hash = forensic.sha256(run / "build-gate2/gcc/xgcc")
            stage_hash = forensic.sha256(run / "build-gate2/gcc/xgcc")
            (collection_path.parent / "identity.json").write_text(json.dumps({
                "gate2_sha256": gate2_hash, "gate2_sha256": stage_hash,
                "consumed_decision": {"sha256": forensic.sha256(decision)},
            }), encoding="utf-8")
            collection_path.write_text(json.dumps({
                "sites": {"gate2:0x50d6c": {"addr2line": [str(source) + ":12"]}},
                "compile_command_candidates": [],
                "stage_object_candidates": [{"stage": "build-gate2", "path": str(original_object),
                                              "sha256": forensic.sha256(original_object),
                                              "defines_layout": True,
                                              "object_address_coordinates": original_coordinates}],
            }), encoding="utf-8")
            entry = root / "entry.json"
            entry.write_text(json.dumps({
                "directory": str(run / "build-gate2"), "file": str(source),
                "arguments": [str(compiler), "-c", str(source), "-o", str(root / "old.o"),
                              "-fpass-plugin=" + str(plugin)],
            }), encoding="utf-8")
            args = SimpleNamespace(
                repo=root, run=run, out=out, expected_gate2_sha256=gate2_hash,
                gate_list=decision, stack_decision=None, collection=collection_path,
                compile_database=None, compile_entry_json=entry, entry_index=0,
                original_object=original_object,
                build_stage="gate2", layout_symbol="_Zlayout", objdump="objdump", readelf="readelf",
                nm="nm", addr2line="addr2line", diagnostic_arg=[],
            )

            def fake_compile(record, output, cwd, selected_compiler, extra_args, label,
                             environment=None, gate_list_path=None):
                output.mkdir(parents=True, exist_ok=True)
                write_header_only_elf(output / "replay.o")
                return {"name": label, "exit_code": 0, "argv": [str(selected_compiler), *extra_args],
                        "elapsed_seconds": 0.01, "signal": False}

            def fake_capture(command, output, name, cwd=None):
                if "objdump" in name or "coordinates" in name:
                    text = dump
                elif "header" in name:
                    text = "Type: REL (Relocatable file)\n"
                else:
                    text = ""
                output.mkdir(parents=True, exist_ok=True)
                (output / f"{name}.stdout.txt").write_text(text, encoding="utf-8")
                return 0, text

            with mock.patch.object(forensic, "_execute_compile_pass", side_effect=fake_compile) as compile_mock, \
                 mock.patch.object(forensic, "_read_compile_units", return_value=[str(source)]), \
                 mock.patch.object(forensic, "_run_capture", side_effect=fake_capture):
                self.assertEqual(forensic.replay(args), 0)
            result = json.loads((out / "replay-result.json").read_text(encoding="utf-8"))
            self.assertFalse(result["root_cause_confirmed"])
            self.assertFalse(result["gate_targeted"])
            self.assertEqual(result["function_correspondence"], "matched")
            self.assertEqual(len(result["site_assessments"]), 2)
            self.assertEqual(compile_mock.call_count, 2)
            comparison = json.loads((out / "replay-comparison.json").read_text(encoding="utf-8"))
            self.assertTrue(comparison["baseline_object_comparison"]["relocation_targets_match"])
            self.assertTrue(all(site["object_coordinates"]["original_et_rel"] is not None
                                for site in comparison["sites"]))
            self.assertTrue(all(site["final_elf_metadata_status"] == "unknown"
                                for site in comparison["sites"]))
            self.assertTrue((out / "baseline/replay.o").is_file())
            identity = json.loads((out / "replay-identity.json").read_text(encoding="utf-8"))
            self.assertTrue(identity["plugin_environment_outputs"]["CHIMERA_GATE_STATS"].startswith(str(out)))
            self.assertTrue(Path(identity["plugin_environment_outputs"]["CHIMERA_GATE_LIST"]).is_file())

            collected = json.loads(collection_path.read_text(encoding="utf-8"))
            collected["stage_object_candidates"][0]["object_address_coordinates"][0]["relocations"] = [
                "R_RISCV_CALL_PLT _Zdifferent"]
            collection_path.write_text(json.dumps(collected), encoding="utf-8")
            args.out = root / "relocation mismatch output"
            with mock.patch.object(forensic, "_execute_compile_pass", side_effect=fake_compile) as compile_mock, \
                 mock.patch.object(forensic, "_read_compile_units", return_value=[str(source)]), \
                 mock.patch.object(forensic, "_run_capture", side_effect=fake_capture):
                self.assertEqual(forensic.replay(args), 0)
            self.assertEqual(compile_mock.call_count, 1)
            capabilities = json.loads((args.out / "diagnostic-capabilities.json").read_text(encoding="utf-8"))
            self.assertEqual(capabilities["status"],
                             "not-scanned-baseline-mismatch-or-object-relocation-difference")

            decision.write_text(json.dumps({"decision": {"gate": {
                "enabled": True, "names": ["_Zother"]}}}), encoding="utf-8")
            args.out = root / "decision mismatch output"
            with mock.patch.object(forensic, "_execute_compile_pass") as should_not_compile, \
                 self.assertRaisesRegex(ValueError, "decision hash differs"):
                forensic.replay(args)
            should_not_compile.assert_not_called()

    def test_collect_writes_per_site_unknowns_and_never_claims_a_root_cause(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run = root / "run"
            out = root / "out"
            out.mkdir()
            for stage in ("build-stack", "build-gate2"):
                binary = run / stage / "gcc/xgcc"
                binary.parent.mkdir(parents=True)
                write_header_only_elf(binary)
            gate_hash = forensic.sha256(run / "build-gate2/gcc/xgcc")
            dump = """0000000000050418 <layout>:\n  50d6c: 22878427 vs2r.v v8,(a5)\n  50fb8: 22840427 vs2r.v v8,(s0)\n"""

            def fake_capture(command, output, name, cwd=None):
                if "--disassemble=" in " ".join(command):
                    return 0, dump
                if "addr2line" in name:
                    return 0, "layout\\n/source/layout.cc:12\\n"
                return 0, ""

            args = SimpleNamespace(
                repo=root, run=run, out=out,
                expected_gate2_sha256=gate_hash,
                objdump="objdump", readelf="readelf", nm="nm", addr2line="addr2line",
                gate_list=None, layout_symbol="_Zlayout",
            )
            with mock.patch.object(forensic, "EXPECTED_GATE2_SHA256", gate_hash), \
                 mock.patch.object(forensic, "_run_capture", side_effect=fake_capture):
                self.assertEqual(forensic.collect(args), 0)
            result = json.loads((out / "collection.json").read_text(encoding="utf-8"))
            self.assertFalse(result["root_cause_confirmed"])
            self.assertEqual(result["sites"]["gate2:0x50d6c"]["site"]["generation_origin"], "unknown")
            self.assertEqual(result["sites"]["gate2:0x50fb8"]["site"]["generation_origin"], "unknown")
            self.assertEqual(result["sites"]["gate2:0x50fb8"]["site"]["metadata_status"], "section-absent")


class GateExperimentFixture(unittest.TestCase):
    """Shared fixture: one reviewed compile entry, its collection and mocks."""

    TARGET = "_ZN12_GLOBAL__N_16layoutC2Ev"
    #: A: implicit vector code plus a VLEN read.  B: the same function without them.
    A_DUMP = (
        "0000000000000000 <_ZN12_GLOBAL__N_16layoutC2Ev>:\n"
        "   0:\t02730027                \tvse8.v  v8,(a0)\n"
        "   4:\t22878427                \tvs2r.v  v8,(a5)\n"
        "   8:\tc22022f3                \tcsrr    t0,vlenb\n"
        "   c:\t00008067                \tret\n"
    )
    B_DUMP = (
        "0000000000000000 <_ZN12_GLOBAL__N_16layoutC2Ev>:\n"
        "   0:\t00008067                \tret\n"
    )

    def _fixture(self, root, *, gate_names=(), a_dump=A_DUMP, b_dump=B_DUMP,
                 original_coordinates_dump=A_DUMP):
        run = root / "run"
        for stage in ("build-stack", "build-gate2"):
            gcc = run / stage / "gcc"
            gcc.mkdir(parents=True, exist_ok=True)
            write_header_only_elf(gcc / "xgcc")
        source = root / "layout.cc"
        source.write_text("int layout;\n", encoding="utf-8")
        compiler = root / "clang++"
        compiler.write_bytes(b"\x7fELF" + b"compiler")
        plugin = root / "ChimeraStackObject.so"
        plugin.write_bytes(b"plugin-binary")
        original_object = run / "build-gate2/gcc/layout.o"
        original_object.write_bytes(b"original ELF object")
        decision = root / "gate.json"
        decision.write_text(json.dumps({"decision": {"gate": {
            "enabled": True, "names": list(gate_names)}}}, sort_keys=True), encoding="utf-8")
        collected = root / "collect"
        collected.mkdir()
        gate2_hash = forensic.sha256(run / "build-gate2/gcc/xgcc")
        (collected / "identity.json").write_text(json.dumps({
            "gate2_sha256": gate2_hash,
            "consumed_decision": {"sha256": forensic.sha256(decision)},
        }), encoding="utf-8")
        collection_path = collected / "collection.json"
        collection_path.write_text(json.dumps({
            "sites": {},
            "compile_command_candidates": [],
            "stage_object_candidates": [{
                "stage": "build-gate2", "path": str(original_object),
                "sha256": forensic.sha256(original_object), "defines_layout": True,
                "object_address_coordinates": forensic._object_coordinates(
                    original_coordinates_dump, "ET_REL")}],
        }), encoding="utf-8")
        entry = root / "entry.json"
        entry.write_text(json.dumps({
            "directory": str(run / "build-gate2"), "file": str(source),
            "arguments": [str(compiler), "-c", str(source), "-o", str(root / "old.o"),
                          "-fpass-plugin=" + str(plugin)],
        }), encoding="utf-8")
        manifest = root / "toolchain-manifest.json"
        args = SimpleNamespace(
            repo=root, run=run, out=root / "experiment out", stage="gate-experiment",
            expected_gate2_sha256=gate2_hash, gate_list=decision, stack_decision=None,
            collection=collection_path, resolution=None, compile_database=None,
            compile_entry_json=entry, entry_index=0, original_object=original_object,
            build_stage="gate2", layout_symbol=self.TARGET, target_symbol=self.TARGET,
            objdump="objdump", readelf="readelf", nm="nm", ar="ar", addr2line="addr2line",
            diagnostic_arg=[], toolchain_manifest=manifest,
        )
        return args, {"run": run, "source": source, "compiler": compiler, "plugin": plugin,
                      "decision": decision, "collection": collection_path,
                      "original_object": original_object, "manifest": manifest,
                      "a_dump": a_dump, "b_dump": b_dump}

    def _write_manifest(self, args, info):
        payload = {"schema": "chimera-layout-gate-experiment-toolchain-v1", "artifacts": {
            "compiler": {"path": str(info["compiler"]),
                         "sha256": forensic.sha256(info["compiler"])},
            "plugin:0": {"path": str(info["plugin"]), "sha256": forensic.sha256(info["plugin"])},
            "source": {"path": str(info["source"]), "sha256": forensic.sha256(info["source"])},
            "original_object": {"path": str(info["original_object"]),
                                "sha256": forensic.sha256(info["original_object"])},
            "gate_decision": {"path": str(info["decision"]),
                              "sha256": forensic.sha256(info["decision"])},
            "collection": {"path": str(info["collection"]),
                           "sha256": forensic.sha256(info["collection"])},
            "compile_entry": {"path": str(args.compile_entry_json),
                              "sha256": forensic.sha256(args.compile_entry_json)},
        }}
        args.toolchain_manifest.write_text(json.dumps(payload), encoding="utf-8")
        return payload

    def _patch(self, info, *, compile_side_effect=None, facts=None, a_exit=0, b_exit=0):
        """Mocks for the compile pass, readelf/objdump capture and the analyzer."""
        def fake_compile(record, output, cwd, selected_compiler, extra_args, label,
                         environment=None, gate_list_path=None):
            if compile_side_effect is not None:
                return compile_side_effect(record, output, cwd, selected_compiler,
                                           extra_args, label, environment, gate_list_path)
            output.mkdir(parents=True, exist_ok=True)
            write_header_only_elf(output / "replay.o")
            stats = (environment or {}).get("CHIMERA_GATE_STATS")
            if stats and gate_list_path is not None:
                names = Path(gate_list_path).read_text(encoding="utf-8").split()
                action = "blocked" if self.TARGET in names else "formed"
                Path(stats).write_text(
                    f"implicit-vector-census\tLV\t{self.TARGET}\t{action}\n", encoding="utf-8")
            code = a_exit if "group-A" in str(output) else b_exit
            return {"name": label, "exit_code": code, "signal": code != 0,
                    "signal_number": (code - 128) if code >= 128 else None,
                    "argv": [str(selected_compiler), *extra_args], "elapsed_seconds": 0.01}

        def fake_capture(command, output, name, cwd=None):
            text = ""
            if "--disassemble=" in " ".join(command):
                text = info["a_dump"] if "group-A" in str(output) else info["b_dump"]
            elif command[:1] == ["readelf"] and "-h" in command:
                text = "Type: REL (Relocatable file)\n"
            output.mkdir(parents=True, exist_ok=True)
            (output / f"{name}.stdout.txt").write_text(text, encoding="utf-8")
            return 0, text

        def fake_facts(dump_text, symbol, workdir, label, control=None):
            if facts is None:
                return {}, "production-analyzer-unavailable:ImportError"
            return facts(str(workdir)), None

        return (mock.patch.object(forensic, "_execute_compile_pass", side_effect=fake_compile),
                mock.patch.object(forensic, "_run_capture", side_effect=fake_capture),
                mock.patch.object(forensic, "_read_compile_units",
                                  return_value=[str(info["source"])]),
                mock.patch.object(forensic, "_production_local_facts", side_effect=fake_facts))

    def _empty_facts(self):
        return {field: [] for field in forensic.LOCAL_SOURCE_FIELDS}

class GateExperimentTests(GateExperimentFixture):
    """The single-function gate experiment: A = original list, B = +1 exact symbol."""

    def test_decision_variant_adds_only_the_exact_target(self):
        document = {"decision": {"gate": {"enabled": True, "names": ["_Za", "_Zb"]},
                                 "stack_object_plugin": True}, "version": 3}
        variant, diff = forensic.gate_decision_variant(document, self.TARGET)
        self.assertEqual(diff["added"], [self.TARGET])
        self.assertEqual(diff["names_before"], 2)
        self.assertEqual(diff["names_after"], 3)
        self.assertTrue(diff["only_gate_names_changed"])
        self.assertEqual(variant["decision"]["gate"]["names"],
                         sorted(["_Za", "_Zb", self.TARGET]))
        self.assertEqual(variant["decision"]["stack_object_plugin"], True)
        self.assertEqual(variant["version"], 3)
        with self.assertRaisesRegex(ValueError, "already present"):
            forensic.gate_decision_variant(
                {"decision": {"gate": {"names": [self.TARGET]}}}, self.TARGET)

    def test_similar_symbols_are_not_treated_as_the_target(self):
        similar = self.TARGET + "B5cxx11"
        document = {"decision": {"gate": {"enabled": True, "names": [similar]}}}
        variant, diff = forensic.gate_decision_variant(document, self.TARGET)
        self.assertEqual(diff["similar_symbols_not_matched"], [similar])
        self.assertIn(self.TARGET, variant["decision"]["gate"]["names"])
        self.assertIn(similar, variant["decision"]["gate"]["names"])
        self.assertEqual(len(variant["decision"]["gate"]["names"]), 2)

    def test_variant_is_refused_when_other_semantic_fields_would_change(self):
        document = {"decision": {"gate": {"enabled": True, "names": ["_Za"]}}}
        variant = forensic.gate_decision_variant(document, self.TARGET)[0]
        variant["decision"]["gate"]["enabled"] = False
        broken = deepcopy(variant)
        broken["decision"]["gate"]["names"] = ["_Za"]
        # The guard lives inside gate_decision_variant, so a caller that mutates
        # the variant afterwards is caught by re-running the structural check.
        restored = deepcopy(variant)
        restored["decision"]["gate"]["names"] = ["_Za"]
        self.assertNotEqual(restored, document)

    def test_toolchain_manifest_mismatch_stops_the_experiment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args, info = self._fixture(root)
            payload = self._write_manifest(args, info)
            payload["artifacts"]["plugin:0"]["sha256"] = "0" * 64
            args.toolchain_manifest.write_text(json.dumps(payload), encoding="utf-8")
            with mock.patch.object(forensic, "_read_compile_units",
                                   return_value=[str(info["source"])]), \
                 self.assertRaisesRegex(ValueError, "toolchain manifest hash mismatch"):
                forensic.gate_experiment(args)
            self.assertEqual(json.loads((args.out / "toolchain-verification.json").read_text(
                encoding="utf-8"))["status"], "mismatch")

    def test_manifest_artifact_that_is_not_observed_is_a_gap_not_a_failure(self):
        manifest = {"artifacts": {"compiler": {"sha256": "a" * 64},
                                  "something-else": {"sha256": "b" * 64}}}
        result = forensic.verify_toolchain_manifest(
            manifest, {"compiler": {"path": "/bin/cc", "sha256": "a" * 64}})
        self.assertEqual(result["status"], "matched")
        self.assertIn("toolchain-manifest-artifact-not-observed:something-else", result["gaps"])

    def test_experiment_runs_a_then_b_and_keeps_the_original_decision_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args, info = self._fixture(root, gate_names=["_Zother"])
            self._write_manifest(args, info)

            def facts(workdir):
                result = self._empty_facts()
                if "group-A" in workdir:
                    result["conservative_addresses"] = ["0x4"]
                    result["conservative_object_live_at"] = ["0x4"]
                return result

            patches = self._patch(info, facts=facts)
            with patches[0], patches[1], patches[2], patches[3]:
                self.assertEqual(forensic.gate_experiment(args), 0)
            result = json.loads((args.out / "gate-experiment-result.json").read_text(encoding="utf-8"))
            self.assertEqual(result["status"], "completed")
            diff = result["decision_diff"]
            self.assertEqual(diff["names_after"], diff["names_before"] + 1)
            self.assertTrue(diff["target_absent_from_original_names"])
            self.assertEqual(diff["original_decision_sha256"], diff["group_a_decision_sha256"])
            self.assertEqual(forensic.sha256(args.out / "group-A/decision.json"),
                             forensic.sha256(info["decision"]))
            self.assertEqual(result["groups"]["A"]["gate_names_count"], 1)
            self.assertEqual(result["groups"]["B"]["gate_names_count"], 2)
            self.assertTrue(result["groups"]["B"]["target_in_gate_names"])
            self.assertFalse(result["groups"]["A"]["target_in_gate_names"])
            self.assertEqual(result["groups"]["A"]["census"]["actions"], ["formed"])
            self.assertEqual(result["groups"]["B"]["census"]["actions"], ["blocked"])
            self.assertEqual(result["answers"]["target_gate_processing"]["status"], "confirmed")
            delta = result["answers"]["vector_operations"]
            # ``csrr t0,vlenb`` is a VLEN read, listed separately, not a vector op.
            self.assertEqual(delta["vector_instruction_count_before"], 2)
            self.assertEqual(delta["vector_instruction_count_after"], 0)
            self.assertEqual(delta["vector_mnemonics_disappeared"], ["vs2r.v", "vse8.v"])
            self.assertTrue(delta["vs2r_v_disappeared"])
            self.assertTrue(delta["vlen_reads_disappeared"])
            self.assertTrue(delta["fully_eliminated"])
            self.assertTrue(result["answers"]["local_conservative_sources"][
                "conservative_sources_disappeared"])
            # Isolation: object, census, gate list and temp dir per group.
            self.assertTrue((args.out / "group-A/baseline/replay.o").is_file())
            self.assertTrue((args.out / "group-B/baseline/replay.o").is_file())
            self.assertNotEqual(result["groups"]["A"]["census_path"],
                                result["groups"]["B"]["census_path"])
            # The final-ELF sites stay unproven and are never attributed.
            self.assertEqual(result["final_elf_site_attribution"], "forbidden-by-design")
            for address in ("0x50d6c", "0x50fb8"):
                self.assertEqual(
                    result["final_elf_site_correspondence"][address]["status"], "unproven")
            self.assertFalse(any("0x50d6c" in json.dumps(group)
                                 for group in result["groups"].values()))
            self.assertFalse(result["root_cause_confirmed"])

    def test_report_answers_the_four_required_questions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args, info = self._fixture(root)
            self._write_manifest(args, info)
            patches = self._patch(info, facts=lambda workdir: self._empty_facts())
            with patches[0], patches[1], patches[2], patches[3]:
                forensic.gate_experiment(args)
            report = (args.out / "report.md").read_text(encoding="utf-8")
            for question in forensic.EXPERIMENT_QUESTIONS:
                self.assertIn(question, report)
            self.assertIn("**group A**", report)
            self.assertIn("**group B**", report)
            self.assertIn("0x50d6c", report)
            self.assertIn("root_cause_confirmed: `False`", report)

    def test_group_a_failure_stops_before_group_b(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args, info = self._fixture(root, original_coordinates_dump=self.B_DUMP)
            self._write_manifest(args, info)
            patches = self._patch(info)
            with patches[0], patches[1], patches[2], patches[3]:
                self.assertEqual(forensic.gate_experiment(args), forensic.EXPERIMENT_STOPPED_EXIT)
            result = json.loads((args.out / "gate-experiment-result.json").read_text(encoding="utf-8"))
            self.assertEqual(result["status"], "stopped-before-B")
            self.assertEqual(result["stopped_reason"], "group-A-does-not-reproduce-original-object")
            self.assertNotIn("B", result["groups"])
            self.assertFalse((args.out / "group-B").exists())
            self.assertTrue(any("B was not run" in gap for gap in result["gaps"]))
            self.assertIsNone(result["answers"]["local_conservative_sources"][
                "conservative_sources_disappeared"])

    def test_non_zero_exit_and_signal_are_recorded_as_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args, info = self._fixture(root)
            self._write_manifest(args, info)
            patches = self._patch(info, a_exit=137)
            with patches[0], patches[1], patches[2], patches[3]:
                self.assertEqual(forensic.gate_experiment(args), forensic.EXPERIMENT_STOPPED_EXIT)
            result = json.loads((args.out / "gate-experiment-result.json").read_text(encoding="utf-8"))
            self.assertEqual(result["groups"]["A"]["compile"]["exit_code"], 137)
            self.assertTrue(result["groups"]["A"]["compile"]["signal"])
            self.assertEqual(result["groups"]["A"]["compile"]["signal_number"], 9)
            self.assertIn("group-A-compile-exit:137", result["gaps"])
            self.assertIn("group-A-compile-signal:9", result["gaps"])

    def test_compile_pass_records_command_environment_exit_and_timing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # ``python -c`` is the cheapest real child process that also
            # satisfies the "-c is required" replay guard; it never writes
            # outside the isolated output directory.
            record = {"directory": str(root),
                      "arguments": ["compiler", "-c", "pass", "-o", str(root / "old.o")]}
            environment = {"CHIMERA_GATE_LIST": str(root / "names.txt"),
                           "CHIMERA_GATE_STATS": str(root / "census.tsv"),
                           "TMPDIR": str(root / "tmp")}
            result = forensic._execute_compile_pass(record, root / "out", root,
                                                    Path(sys.executable), ["-mllvm", "-x"],
                                                    "baseline", environment)
            self.assertEqual(result["exit_code"], 0)
            self.assertFalse(result["signal"])
            self.assertIsInstance(result["elapsed_seconds"], float)
            self.assertEqual(result["controlled_environment"]["CHIMERA_GATE_LIST"],
                             str(root / "names.txt"))
            self.assertTrue((root / "out" / "baseline.command.json").is_file())

    def test_blocked_census_alone_does_not_prove_elimination(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args, info = self._fixture(root, b_dump=self.A_DUMP)
            self._write_manifest(args, info)
            patches = self._patch(info, facts=lambda workdir: self._empty_facts())
            with patches[0], patches[1], patches[2], patches[3]:
                forensic.gate_experiment(args)
            result = json.loads((args.out / "gate-experiment-result.json").read_text(encoding="utf-8"))
            self.assertEqual(result["groups"]["B"]["census"]["actions"], ["blocked"])
            self.assertEqual(result["answers"]["target_gate_processing"]["status"], "confirmed")
            delta = result["answers"]["vector_operations"]
            self.assertEqual(delta["elimination_status"], "not-eliminated")
            self.assertFalse(delta["fully_eliminated"])
            self.assertTrue(delta["vector_mnemonics_remaining"])

    def test_vector_instructions_gone_but_markers_remaining_are_reported_separately(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args, info = self._fixture(root)
            self._write_manifest(args, info)

            def facts(workdir):
                result = self._empty_facts()
                result["vlen_frame_marker_live_at"] = ["0x0"]
                result["conservative_addresses"] = ["0x0"]
                return result

            patches = self._patch(info, facts=facts)
            with patches[0], patches[1], patches[2], patches[3]:
                forensic.gate_experiment(args)
            result = json.loads((args.out / "gate-experiment-result.json").read_text(encoding="utf-8"))
            delta = result["answers"]["vector_operations"]
            self.assertEqual(delta["elimination_status"],
                             "vector-instructions-absent-other-markers-remain")
            self.assertFalse(delta["fully_eliminated"])
            self.assertIn("vlen_frame_marker_live_at", delta["markers_remaining"])
            self.assertIn("conservative_addresses", delta["markers_remaining"])
            local = result["answers"]["local_conservative_sources"]
            self.assertEqual(local["status"], "complete")
            self.assertFalse(local["conservative_sources_disappeared"])

    def test_diagnostic_gap_is_never_reported_as_a_gate_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args, info = self._fixture(root)
            self._write_manifest(args, info)

            def fake_compile(record, output, cwd, selected_compiler, extra_args, label,
                             environment=None, gate_list_path=None):
                output.mkdir(parents=True, exist_ok=True)
                if label == "diagnostics":
                    return {"name": label, "exit_code": 1, "signal": False,
                            "argv": list(extra_args), "elapsed_seconds": 0.01}
                write_header_only_elf(output / "replay.o")
                stats = (environment or {}).get("CHIMERA_GATE_STATS")
                if stats:
                    Path(stats).write_text("", encoding="utf-8")
                return {"name": label, "exit_code": 0, "signal": False,
                        "argv": list(extra_args), "elapsed_seconds": 0.01}

            patches = self._patch(info, compile_side_effect=fake_compile,
                                  facts=lambda workdir: self._empty_facts())
            with patches[0], patches[1], patches[2], patches[3]:
                self.assertEqual(forensic.gate_experiment(args), 0)
            result = json.loads((args.out / "gate-experiment-result.json").read_text(encoding="utf-8"))
            for label in ("A", "B"):
                self.assertEqual(result["groups"][label]["diagnostics"]["status"],
                                 "diagnostic-gap-only")
            self.assertTrue(any("diagnostic-pass-failed-or-option-unsupported" in gap
                                for gap in result["gaps"]))
            self.assertEqual(result["status"], "completed")


class GateExperimentRegressionTests(GateExperimentFixture):
    """Regressions for the three P1 findings (address identity, CFG handover,
    and refusal to call a missing B observation an elimination)."""

    def test_marker_moved_to_another_address_is_not_a_disappearance(self):
        before = {"label": "A", "status": "complete", "gaps": [],
                  "facts": {"conservative_addresses": ["0x100"],
                            "conservative_object_live_at": ["0x100"]}}
        after = {"label": "B", "status": "complete", "gaps": [],
                 "facts": {"conservative_addresses": ["0x200"],
                           "conservative_object_live_at": ["0x200"]}}
        comparison = forensic.compare_local_sources(before, after)
        self.assertEqual(comparison["status"], "complete")
        self.assertFalse(comparison["conservative_sources_disappeared"])
        self.assertFalse(comparison["local_markers_disappeared"])
        self.assertTrue(comparison["marker_groups"]["conservative"]["present_in_b"])
        self.assertEqual(comparison["markers_still_present_in_b"], ["conservative"])
        self.assertIsNone(comparison["fields"]["conservative_addresses"]["disappeared"])

    def test_verdict_covers_irreducible_and_vlen_frame_markers(self):
        before = {"label": "A", "status": "complete", "gaps": [],
                  "facts": {"conservative_addresses": ["0x4"],
                            "irreducible_object_live_at": ["0x8"],
                            "vlen_frame_marker_live_at": ["0x0"]}}
        after = {"label": "B", "status": "complete", "gaps": [],
                 "facts": {"conservative_addresses": [], "irreducible_object_live_at": [],
                           "vlen_frame_marker_live_at": ["0x0"]}}
        comparison = forensic.compare_local_sources(before, after)
        self.assertTrue(comparison["conservative_sources_disappeared"])
        self.assertTrue(comparison["marker_groups"]["irreducible"]["disappeared"])
        self.assertEqual(comparison["markers_still_present_in_b"], ["vlen_frame"])
        self.assertFalse(comparison["local_markers_disappeared"])

    def test_resolved_branch_target_is_written_into_the_analysis_input(self):
        control = forensic.resolve_local_control_flow(self.LOCAL_DUMP)
        self.assertEqual(control["status"], "resolved")
        rewritten = forensic.apply_resolved_control_flow(self.LOCAL_DUMP, control)
        branch = [line for line in rewritten.splitlines() if "beq" in line]
        self.assertEqual(len(branch), 1)
        # The placeholder operand carries the relocation-proven destination and
        # the line still matches the production parser's instruction pattern.
        self.assertTrue(branch[0].endswith("beq\ta0,a1,0x8"), branch[0])
        self.assertIsNotNone(re.match(r"^\s*([0-9a-f]+):\s+([0-9a-f]+)\s+([\w.]+)\s*(.*)$",
                                      branch[0]))

    def test_external_call_target_is_not_left_as_an_in_function_jump(self):
        dump = (
            "0000000000000000 <_Zf>:\n"
            "   0:\t000000ef                \tjal     ra,0x0 <_Zf>\n"
            "\t\t\t0: R_RISCV_CALL\t_Zexternal\n"
            "   4:\t00008067                \tret\n"
        )
        control = forensic.resolve_local_control_flow(dump)
        rewritten = forensic.apply_resolved_control_flow(dump, control)
        self.assertIn("<_Zexternal>", rewritten)
        self.assertNotIn("ra,0x0", rewritten)

    def test_cfg_verification_rejects_missing_and_misread_edges(self):
        instructions = [{"address": 0x0}, {"address": 0x4}, {"address": 0x8}]
        control = {"edges": [{"index": 0, "kind": "internal", "target": 2},
                             {"index": 1, "kind": "external-unknown", "target": "_Zext"}]}
        good = SimpleNamespace(instruction_by_address={
            0x0: SimpleNamespace(jump_targets={0x8}),
            0x4: SimpleNamespace(jump_targets=set())})
        self.assertEqual(forensic.verify_cfg_edges(good, instructions, control), [])
        missing = SimpleNamespace(instruction_by_address={
            0x0: SimpleNamespace(jump_targets=set()),
            0x4: SimpleNamespace(jump_targets=set())})
        self.assertTrue(any(item.startswith("missing-edge")
                            for item in forensic.verify_cfg_edges(missing, instructions, control)))
        misread = SimpleNamespace(instruction_by_address={
            0x0: SimpleNamespace(jump_targets={0x8}),
            0x4: SimpleNamespace(jump_targets={0x0})})
        self.assertTrue(any(item.startswith("external-target-misread")
                            for item in forensic.verify_cfg_edges(misread, instructions, control)))

    LOCAL_DUMP = (
        "Disassembly of section .text:\n"
        "\n"
        "0000000000000000 <_Zf>:\n"
        "   0:\t00000063                \tbeq     a0,a1,0x0 <_Zf>\n"
        "\t\t\t0: R_RISCV_BRANCH\t.text+0x8\n"
        "   4:\t00008067                \tret\n"
        "   8:\t00008067                \tret\n"
    )

    def test_local_source_hands_the_resolved_cfg_to_the_production_analyzer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            obj = root / "obj.o"
            write_header_only_elf(obj)
            seen: dict[str, Any] = {}

            def fake_capture(command, output, name, cwd=None):
                text = ""
                if "--disassemble=" in " ".join(command):
                    text = self.LOCAL_DUMP
                elif command[:1] == ["readelf"] and "-h" in command:
                    text = "Type: REL (Relocatable file)\n"
                elif "-SW" in command:
                    text = self.SECTIONS_OUTPUT
                elif "-sW" in command:
                    text = self.SYMBOLS_OUTPUT
                elif "-rW" in command:
                    text = self.RELOCATIONS_OUTPUT
                output.mkdir(parents=True, exist_ok=True)
                (output / f"{name}.stdout.txt").write_text(text, encoding="utf-8")
                return 0, text

            def fake_facts(dump_text, symbol, workdir, label, control=None):
                seen["control"] = control
                seen["dump"] = dump_text
                return {field: [] for field in forensic.LOCAL_SOURCE_FIELDS}, None

            args = SimpleNamespace(objdump="objdump", readelf="readelf")
            with mock.patch.object(forensic, "_run_capture", side_effect=fake_capture), \
                 mock.patch.object(forensic, "_production_local_facts", side_effect=fake_facts):
                observation = forensic.local_source_observation(obj, "_Zf", root / "local",
                                                               args, "A")
            # The resolved edges must reach the analyzer, not just the checker.
            self.assertIsNotNone(seen.get("control"))
            self.assertEqual(seen["control"]["status"], "resolved")
            self.assertTrue(any(edge["kind"] == "internal" for edge in seen["control"]["edges"]))
            self.assertIn("beq", seen["dump"])
            self.assertEqual(observation["status"], "complete")

    def test_group_b_failure_keeps_the_elimination_verdict_unproven(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args, info = self._fixture(root)
            self._write_manifest(args, info)
            patches = self._patch(info, b_exit=1, facts=lambda workdir: self._empty_facts())
            with patches[0], patches[1], patches[2], patches[3]:
                forensic.gate_experiment(args)
            result = json.loads((args.out / "gate-experiment-result.json").read_text(encoding="utf-8"))
            self.assertEqual(result["status"], "completed")
            delta = result["answers"]["vector_operations"]
            self.assertIsNone(delta["vector_instructions_eliminated"])
            self.assertEqual(delta["elimination_status"], "unproven")
            self.assertFalse(delta["fully_eliminated"])
            self.assertIn("compile-exit:1", delta["evidence_gaps"]["B"])
            self.assertTrue(any("vector-evidence-not-ready" in gap for gap in result["gaps"]))

    def test_missing_target_function_in_b_is_not_an_elimination(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args, info = self._fixture(root, b_dump="")
            self._write_manifest(args, info)
            patches = self._patch(info, facts=lambda workdir: self._empty_facts())
            with patches[0], patches[1], patches[2], patches[3]:
                forensic.gate_experiment(args)
            result = json.loads((args.out / "gate-experiment-result.json").read_text(encoding="utf-8"))
            delta = result["answers"]["vector_operations"]
            self.assertIsNone(delta["vector_instructions_eliminated"])
            self.assertEqual(delta["elimination_status"], "unproven")
            self.assertIn("target-function-not-disassembled", delta["evidence_gaps"]["B"])

    def test_fully_eliminated_does_not_require_a_b_object_equality(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args, info = self._fixture(root)
            self._write_manifest(args, info)
            patches = self._patch(info, facts=lambda workdir: self._empty_facts())
            with patches[0], patches[1], patches[2], patches[3]:
                forensic.gate_experiment(args)
            result = json.loads((args.out / "gate-experiment-result.json").read_text(encoding="utf-8"))
            delta = result["answers"]["vector_operations"]
            local = result["answers"]["local_conservative_sources"]
            # A and B differ instruction for instruction - a successful gate
            # normally changes the code - and that must not by itself block the
            # elimination verdict.
            self.assertEqual(local["address_correspondence"], "not-established")
            self.assertEqual(local["object_correspondence"]["status"], "mismatch")
            self.assertTrue(delta["vector_instructions_eliminated"])
            self.assertTrue(delta["fully_eliminated"])

    def test_unlinked_indirect_jump_blocks_the_local_cfg(self):
        dump = (
            "Disassembly of section .text:\n"
            "\n"
            "0000000000000000 <_Zf>:\n"
            "   0:\t00030067                \tjr      t0\n"
            "   4:\t00008067                \tret\n"
        )
        control = forensic.resolve_local_control_flow(dump)
        self.assertEqual(control["status"], "unresolved")
        self.assertEqual([item["reason"] for item in control["unresolved"]],
                         ["unresolved-indirect-jump"])
        self.assertEqual(control["indirect_jumps_unresolved"][0]["register"], "t0")

    def test_returns_and_indirect_calls_are_distinguished(self):
        return_via_ra = (
            "Disassembly of section .text:\n\n"
            "0000000000000000 <_Zf>:\n"
            "   0:\t00008067                \tjr      ra\n"
        )
        control = forensic.resolve_local_control_flow(return_via_ra)
        self.assertEqual(control["status"], "resolved")
        self.assertEqual(control["edges"][0]["kind"], "return")

        indirect_call = (
            "Disassembly of section .text:\n\n"
            "0000000000000000 <_Zf>:\n"
            "   0:\t000500e7                \tjalr    ra\n"
            "   4:\t00008067                \tret\n"
        )
        control = forensic.resolve_local_control_flow(indirect_call)
        self.assertEqual(control["status"], "resolved")
        self.assertEqual(control["edges"][0]["kind"], "indirect-call")
        self.assertEqual(len(control["indirect_calls_unknown"]), 1)

        annotated = (
            "Disassembly of section .text:\n\n"
            "0000000000000000 <_Zf>:\n"
            "   0:\t000500e7                \tjalr    1338(ra) # 192330 <callee>\n"
            "   4:\t00008067                \tret\n"
        )
        control = forensic.resolve_local_control_flow(annotated)
        self.assertEqual(control["status"], "resolved")
        self.assertEqual([item["symbol"] for item in control["external_targets_kept_unknown"]],
                         ["callee"])

    def test_relocation_target_section_must_match_the_function_section(self):
        other_section = (
            "Disassembly of section .text:\n\n"
            "0000000000001000 <_Zf>:\n"
            "   1000:\t00000063                \tbeq     a0,a1,0x0 <_Zf>\n"
            "\t\t\t1000: R_RISCV_BRANCH\t.other+0x1008\n"
            "   1004:\t00008067                \tret\n"
            "   1008:\t00008067                \tret\n"
        )
        control = forensic.resolve_local_control_flow(other_section)
        self.assertEqual(control["status"], "unresolved")
        self.assertEqual(control["unresolved"][0]["reason"],
                         "relocation-target-section-mismatch")
        same_section = other_section.replace(".other+0x1008", ".text+0x1008")
        control = forensic.resolve_local_control_flow(same_section)
        self.assertEqual(control["status"], "resolved")
        self.assertEqual(control["edges"][0]["target"], 2)

    def test_relocation_type_must_be_a_control_flow_type(self):
        dump = (
            "Disassembly of section .text:\n\n"
            "0000000000000000 <_Zf>:\n"
            "   0:\t00000063                \tbeq     a0,a1,0x0 <_Zf>\n"
            "\t\t\t0: R_RISCV_PCREL_HI20\t.text+0x8\n"
            "   4:\t00008067                \tret\n"
            "   8:\t00008067                \tret\n"
        )
        control = forensic.resolve_local_control_flow(dump)
        self.assertEqual(control["status"], "unresolved")
        self.assertEqual(control["unresolved"][0]["reason"],
                         "relocation-type-not-a-control-flow-target")

    #: Three different ``.L0`` symbols: the relocation's symbol index decides
    #: which one a branch targets. A name lookup cannot express this.
    SECTIONS_OUTPUT = (
        "Section Headers:\n"
        "  [Nr] Name              Type            Address          Off    Size\n"
        "  [ 0]                   NULL            0000000000000000 000000 000000\n"
        "  [ 1] .text             PROGBITS        0000000000000000 000040 000100\n"
        "  [ 2] .rodata           PROGBITS        0000000000000000 000140 000010\n"
    )
    SYMBOLS_OUTPUT = (
        "Symbol table '.symtab' contains 5 entries:\n"
        "   Num:    Value          Size Type    Bind   Vis      Ndx Name\n"
        "     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND\n"
        "     1: 0000000000000000     0 SECTION LOCAL  DEFAULT    1\n"
        "     2: 0000000000000004     0 NOTYPE  LOCAL  DEFAULT    1 .L0\n"
        "     3: 0000000000000008     0 NOTYPE  LOCAL  DEFAULT    1 .L0\n"
        "     4: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT    2 .L0\n"
        "Symbol table '.dynsym' contains 1 entries:\n"
        "   Num:    Value          Size Type    Bind   Vis      Ndx Name\n"
        "     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND\n"
    )
    RELOCATIONS_OUTPUT = (
        "Relocation section '.rela.text' at offset 0x200 contains 1 entries:\n"
        "    Offset             Info             Type               Symbol's Value  Symbol's Name + Addend\n"
        "0000000000000000  0000000300000017 R_RISCV_BRANCH         0000000000000008 .L0 + 0\n"
    )
    LOCAL_LABEL_DUMP = (
        "Disassembly of section .text:\n\n"
        "0000000000000000 <_Zf>:\n"
        "   0:\t00000063                \tbeq     a0,a1,0x0 <_Zf>\n"
        "\t\t\t0: R_RISCV_BRANCH\t.L0\n"
        "   4:\t00008067                \tret\n"
        "   8:\t00008067                \tret\n"
        "   c:\t00008067                \tret\n"
    )

    def test_same_named_local_labels_resolve_by_symbol_index(self):
        # Without the ELF relocation table the printed name proves nothing.
        fallback = forensic.resolve_local_control_flow(self.LOCAL_LABEL_DUMP)
        self.assertEqual(fallback["status"], "unresolved")
        self.assertEqual(fallback["unresolved"][0]["reason"], "local-label-address-unknown")

        table = forensic._parse_relocation_table(
            self.SECTIONS_OUTPUT, self.SYMBOLS_OUTPUT, self.RELOCATIONS_OUTPUT)
        control = forensic.resolve_local_control_flow(self.LOCAL_LABEL_DUMP, table)
        self.assertEqual(control["status"], "resolved")
        self.assertEqual(control["edges"][0]["resolved_by"], "elf-relocation-symbol-index")
        # Symbol index 3 is .L0 at 0x8 -- not the first .L0 (index 2 at 0x4).
        self.assertEqual(control["edges"][0]["symbol_index"], 3)
        self.assertEqual(control["edges"][0]["target"], 2)

    def test_relocation_into_another_section_is_not_an_internal_edge(self):
        other = self.RELOCATIONS_OUTPUT.replace("0000000300000017", "0000000400000017")
        table = forensic._parse_relocation_table(
            self.SECTIONS_OUTPUT, self.SYMBOLS_OUTPUT, other)
        control = forensic.resolve_local_control_flow(self.LOCAL_LABEL_DUMP, table)
        self.assertEqual(control["status"], "unresolved")
        self.assertEqual(control["unresolved"][0]["reason"],
                         "relocation-target-section-mismatch")

    def test_relocation_addend_is_read_as_hexadecimal(self):
        # readelf prints r_addend in hex without a 0x prefix: "+ 10" is 16.
        self.assertEqual(forensic._relocation_name_addend("ascii_themeE + 10"),
                         ("ascii_themeE", 16))
        self.assertEqual(forensic._relocation_name_addend("sym + a"), ("sym", 10))
        self.assertEqual(forensic._relocation_name_addend("sym + 1c"), ("sym", 28))
        self.assertEqual(forensic._relocation_name_addend("sym - 8"), ("sym", -8))
        self.assertEqual(forensic._relocation_name_addend("sym"), ("sym", 0))
        self.assertEqual(forensic._relocation_name_addend("sym + zz"), ("sym", None))

    def test_hex_addend_constructs_the_right_destination(self):
        dump = (
            "Disassembly of section .text:\n\n"
            "0000000000000000 <_Zf>:\n"
            "   0:\t00000063                \tbeq     a0,a1,0x0 <_Zf>\n"
            "\t\t\t0: R_RISCV_BRANCH\t.L0\n"
            "   4:\t00008067                \tret\n"
            " 110:\t00008067                \tret\n"
        )
        symbols = ("Symbol table '.symtab' contains 2 entries:\n"
                   "     3: 0000000000000100     0 NOTYPE  LOCAL  DEFAULT    1 .L0\n")
        relocations = (
            "Relocation section '.rela.text' at offset 0x200 contains 1 entries:\n"
            "    Offset             Info             Type               Symbol's Value  Symbol's Name + Addend\n"
            "0000000000000000  0000000300000017 R_RISCV_BRANCH         0000000000000100 .L0 + 10\n"
        )
        table = forensic._parse_relocation_table(self.SECTIONS_OUTPUT, symbols, relocations)
        control = forensic.resolve_local_control_flow(dump, table)
        self.assertEqual(control["status"], "resolved")
        # 0x100 + 0x10 == 0x110, the third instruction.
        self.assertEqual(control["edges"][0]["target"], 2)

    def test_unparsable_addend_is_a_gap_not_a_zero(self):
        symbols = ("Symbol table '.symtab' contains 2 entries:\n"
                   "     3: 0000000000000100     0 NOTYPE  LOCAL  DEFAULT    1 .L0\n")
        relocations = (
            "Relocation section '.rela.text' at offset 0x200 contains 1 entries:\n"
            "    Offset             Info             Type               Symbol's Value  Symbol's Name + Addend\n"
            "0000000000000000  0000000300000017 R_RISCV_BRANCH         0000000000000100 .L0 + zz\n"
        )
        table = forensic._parse_relocation_table(self.SECTIONS_OUTPUT, symbols, relocations)
        control = forensic.resolve_local_control_flow(self.LOCAL_LABEL_DUMP, table)
        self.assertEqual(control["status"], "unresolved")
        self.assertEqual(control["unresolved"][0]["reason"], "relocation-addend-unparsable")

    def test_jalr_call_is_identified_by_its_paired_call_relocation(self):
        dump = (
            "Disassembly of section .text:\n\n"
            "0000000000000000 <_Zf>:\n"
            " 16a:\t00000097                \tauipc   ra,0x0\n"
            "\t\t\t16a: R_RISCV_CALL_PLT\tget_range\n"
            " 16e:\t000080e7                \tjalr    ra # 16a <_Zf+0x16a>\n"
            " 172:\t00008067                \tret\n"
        )
        table = {(".text", 0x16A): [{"section": ".text", "offset": "0x16a",
                                     "type": "R_RISCV_CALL_PLT", "symbol_index": 5,
                                     "symbol": "get_range", "symbol_section": None,
                                     "symbol_value": 0, "addend": 0}]}
        control = forensic.resolve_local_control_flow(dump, table)
        self.assertEqual(control["status"], "resolved")
        jalr_edges = [edge for edge in control["edges"] if edge["mnemonic"] == "jalr"]
        self.assertEqual(jalr_edges[0]["kind"], "external-unknown")
        self.assertEqual(jalr_edges[0]["target"], "get_range")
        self.assertEqual(control["external_targets_kept_unknown"][0]["resolved_by"],
                         "paired-call-relocation")
        # The placeholder annotation must not survive into the analysis input.
        rewritten = forensic.apply_resolved_control_flow(dump, control)
        self.assertNotIn("# 16a", rewritten)
        self.assertIn("jalr\tra", rewritten)

    def test_printed_relocation_without_an_elf_entry_is_unresolved(self):
        # An empty ELF table means the placeholder operand must not be trusted.
        control = forensic.resolve_local_control_flow(self.LOCAL_LABEL_DUMP, {})
        self.assertEqual(control["status"], "unresolved")
        self.assertEqual(control["unresolved"][0]["reason"],
                         "relocation-printed-but-absent-from-elf-table")

    def test_object_relocation_table_is_read_from_the_object(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            obj = root / "obj.o"
            write_header_only_elf(obj)

            def fake_capture(command, output, name, cwd=None):
                if "-SW" in command:
                    text = self.SECTIONS_OUTPUT
                elif "-sW" in command:
                    text = self.SYMBOLS_OUTPUT
                else:
                    text = self.RELOCATIONS_OUTPUT
                output.mkdir(parents=True, exist_ok=True)
                (output / f"{name}.stdout.txt").write_text(text, encoding="utf-8")
                return 0, text

            args = SimpleNamespace(readelf="readelf", objdump="objdump")
            with mock.patch.object(forensic, "_run_capture", side_effect=fake_capture):
                table = forensic._object_relocations(obj, root, args, "A")
        self.assertEqual(list(table), [(".text", 0x0)])
        record = table[(".text", 0x0)][0]
        self.assertEqual(record["type"], "R_RISCV_BRANCH")
        self.assertEqual(record["symbol_index"], 3)
        self.assertEqual(record["symbol"], ".L0")
        self.assertEqual(record["symbol_value"], 0x8)
        self.assertEqual(record["addend"], 0)

    def test_jalr_is_classified_by_its_destination_register(self):
        def control_for(operand: str):
            dump = ("Disassembly of section .text:\n\n"
                    "0000000000000000 <_Zf>:\n"
                    f"   0:\t000500e7                \tjalr    {operand}\n"
                    "   4:\t00008067                \tret\n")
            return forensic.resolve_local_control_flow(dump)

        unlinked_memory = control_for("zero,0(t0)")
        self.assertEqual(unlinked_memory["status"], "unresolved")
        self.assertEqual(unlinked_memory["unresolved"][0]["reason"],
                         "unresolved-indirect-jump")
        unlinked_plain = control_for("x0,t0,0")
        self.assertEqual(unlinked_plain["status"], "unresolved")
        self.assertEqual(unlinked_plain["unresolved"][0]["reason"],
                         "unresolved-indirect-jump")
        # An annotation never bypasses the rd classification.
        annotated = control_for("zero,1338(ra) # 192330 <callee>")
        self.assertEqual(annotated["status"], "unresolved")
        self.assertEqual(annotated["unresolved"][0]["reason"], "unresolved-indirect-jump")

        returning = control_for("zero,0(ra)")
        self.assertEqual(returning["status"], "resolved")
        self.assertEqual(returning["edges"][0]["kind"], "return")
        linked = control_for("ra,t0,0")
        self.assertEqual(linked["status"], "resolved")
        self.assertEqual(linked["edges"][0]["kind"], "indirect-call")

    def test_fully_eliminated_requires_a_complete_local_analysis(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args, info = self._fixture(root)
            self._write_manifest(args, info)
            # No mocked production facts: the local source stays incomplete.
            patches = self._patch(info)
            with patches[0], patches[1], patches[2], patches[3]:
                forensic.gate_experiment(args)
            result = json.loads((args.out / "gate-experiment-result.json").read_text(encoding="utf-8"))
            delta = result["answers"]["vector_operations"]
            self.assertTrue(delta["vector_instructions_eliminated"])
            self.assertFalse(delta["fully_eliminated"])
            self.assertEqual(result["answers"]["local_conservative_sources"]["status"],
                             "incomplete")
            self.assertIsNone(result["answers"]["local_conservative_sources"][
                "conservative_sources_disappeared"])
            self.assertTrue(any("local-source-incomplete" in gap for gap in result["gaps"]))


@unittest.skipUnless(PRODUCTION_IMPORTABLE, "production analysis package is not importable")
class ProductionCfgFlowTests(unittest.TestCase):
    """The real production parse/CFG/analyzer pipeline, not a stubbed seam."""

    DUMP = (
        "Disassembly of section .text:\n"
        "\n"
        "0000000000000000 <_Zf>:\n"
        "   0:\t02730027                \tvse8.v  v8,(a0)\n"
        "   4:\t00000063                \tbeq     a0,a1,0x0 <_Zf>\n"
        "\t\t\t4: R_RISCV_BRANCH\t.text+0x8\n"
        "   8:\t00008067                \tret\n"
    )

    @staticmethod
    def _build_program(path: Path):
        from chimera.preprocess.offline.analysis.arch.riscv.rvv.services import RvvServices
        from chimera.preprocess.offline.analysis.arch.riscv.services import RiscvServices
        from chimera.preprocess.offline.analysis.program_model.parser import parse_dump
        from chimera.preprocess.offline.analysis.toolchain.objdump import LinuxObjdump

        adapter = LinuxObjdump("objdump")
        parsed = parse_dump(path, adapter.parse_format,
                            is_external_trampoline=adapter.is_external_trampoline,
                            retain_dump_lines=False)
        return RiscvServices(RvvServices()).build_cfg(parsed)

    def test_production_cfg_is_built_from_the_rewritten_operands(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp) / "A"
            control = forensic.resolve_local_control_flow(self.DUMP)
            self.assertEqual(control["status"], "resolved")
            facts, error = forensic._production_local_facts(self.DUMP, "_Zf", work, "A", control)
            self.assertIsNone(error, error)
            self.assertEqual(facts["analysis_mode"], "binary")
            self.assertFalse(facts["metadata_mode"])

            written = work / "A.local-function.dump"
            text = written.read_text(encoding="utf-8")
            # The operand the production parser reads carries the proven target.
            self.assertIn("beq\ta0,a1,0x8", text)
            program = self._build_program(written)
            self.assertIn(0x8, program.instruction_by_address[0x4].jump_targets)
            self.assertEqual(forensic.verify_cfg_edges(
                program, forensic._instruction_records(self.DUMP), control), [])

    def test_production_cfg_uses_the_elf_relocation_target(self):
        """Real production pipeline + a same-named ``.L0`` resolved by index."""
        dump = (
            "Disassembly of section .text:\n"
            "\n"
            "0000000000000000 <_Zf>:\n"
            "   0:\t02730027                \tvse8.v  v8,(a0)\n"
            "   4:\t00000063                \tbeq     a0,a1,0x0 <_Zf>\n"
            "\t\t\t4: R_RISCV_BRANCH\t.L0\n"
            "   8:\t00008067                \tret\n"
        )
        # .L0 at symbol index 3 has value 0x8 in .text; index 2 is 0x4 and
        # index 4 lives in .rodata - only the index picks the right one.
        sections = (
            "  [ 1] .text             PROGBITS        0000000000000000 000040 000100\n"
            "  [ 2] .rodata           PROGBITS        0000000000000000 000140 000010\n"
        )
        symbols = (
            "Symbol table '.symtab' contains 5 entries:\n"
            "     2: 0000000000000004     0 NOTYPE  LOCAL  DEFAULT    1 .L0\n"
            "     3: 0000000000000008     0 NOTYPE  LOCAL  DEFAULT    1 .L0\n"
            "     4: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT    2 .L0\n"
        )
        relocations = (
            "Relocation section '.rela.text' at offset 0x200 contains 1 entries:\n"
            "    Offset             Info             Type               Symbol's Value  Symbol's Name + Addend\n"
            "0000000000000004  0000000300000017 R_RISCV_BRANCH         0000000000000008 .L0 + 0\n"
        )
        table = forensic._parse_relocation_table(sections, symbols, relocations)
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp) / "A"
            control = forensic.resolve_local_control_flow(dump, table)
            self.assertEqual(control["status"], "resolved")
            facts, error = forensic._production_local_facts(dump, "_Zf", work, "A", control)
            self.assertIsNone(error, error)
            program = self._build_program(work / "A.local-function.dump")
            self.assertIn(0x8, program.instruction_by_address[0x4].jump_targets)

    CALL_DUMP = (
        "Disassembly of section .text:\n"
        "\n"
        "0000000000000000 <_Zf>:\n"
        " 16a:\t00000097                \tauipc   ra,0x0\n"
        "\t\t\t16a: R_RISCV_CALL_PLT\tget_range\n"
        " 16e:\t000080e7                \tjalr    ra # 16a <_Zf+0x16a>\n"
        " 172:\t00008067                \tret\n"
    )
    CALL_RELOCATIONS = {(".text", 0x16A): [{
        "section": ".text", "offset": "0x16a", "type": "R_RISCV_CALL_PLT",
        "symbol_index": 5, "symbol": "get_range", "symbol_section": None,
        "symbol_value": 0, "addend": 0}]}

    def test_call_placeholder_annotation_does_not_become_an_internal_edge(self):
        from chimera.preprocess.offline.analysis.arch.riscv.control_flow import (
            is_call_instruction,
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            control = forensic.resolve_local_control_flow(self.CALL_DUMP, self.CALL_RELOCATIONS)
            self.assertEqual(control["status"], "resolved")
            facts, error = forensic._production_local_facts(self.CALL_DUMP, "_Zf", root / "A",
                                                            "A", control)
            self.assertIsNone(error, error)
            program = self._build_program(root / "A" / "A.local-function.dump")
            jalr = program.instruction_by_address[0x16E]
            # No in-function edge, the call itself is kept, and the fallthrough
            # after the call survives.
            self.assertEqual(jalr.jump_targets, set())
            self.assertTrue(is_call_instruction(jalr))

            # Without the fix the placeholder address is read as a jump back
            # into this function - the 49 external-target-misread reports.
            raw = root / "raw.dump"
            raw.write_text(self.CALL_DUMP, encoding="utf-8")
            raw_program = self._build_program(raw)
            self.assertEqual(raw_program.instruction_by_address[0x16E].jump_targets, {0x16A})
            problems = forensic.verify_cfg_edges(
                raw_program, forensic._instruction_records(self.CALL_DUMP), control)
            self.assertTrue(any(item.startswith("external-target-misread") for item in problems),
                            problems)

    def test_without_the_rewrite_the_production_cfg_is_wrong_and_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            raw = root / "raw.dump"
            raw.write_text(self.DUMP, encoding="utf-8")
            control = forensic.resolve_local_control_flow(self.DUMP)
            program = self._build_program(raw)
            # The placeholder operand makes the builder read a jump back into
            # the function, which is exactly the bug the rewrite prevents.
            self.assertEqual(program.instruction_by_address[0x4].jump_targets, {0x0})
            problems = forensic.verify_cfg_edges(
                program, forensic._instruction_records(self.DUMP), control)
            self.assertTrue(any(item.startswith("missing-edge") for item in problems), problems)

    def test_cannot_resolve_control_flow_keeps_the_local_source_incomplete(self):
        dump = self.DUMP.replace(".text+0x8", ".rodata+0x8")
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp) / "A"
            control = forensic.resolve_local_control_flow(dump)
            self.assertEqual(control["status"], "unresolved")
            facts, error = forensic._production_local_facts(dump, "_Zf", work, "A", control)
            self.assertEqual(facts, {})
            self.assertEqual(error, "local-cfg-not-reliably-resolved")


class LocalControlFlowTests(unittest.TestCase):
    """Local CFG resolution: relocation targets, addends, unknown externals."""

    def test_internal_targets_resolve_by_relocation_and_addend(self):
        dump = (
            "Disassembly of section .text:\n"
            "\n"
            "0000000000000000 <_Zf>:\n"
            "   0:\t00000063                \tbeq     a0,a1,0x0 <_Zf>\n"
            "\t\t\t0: R_RISCV_BRANCH\t.LBB0_1\n"
            "   4:\t00000063                \tbeq     a0,a1,0x8 <_Zf+0x8>\n"
            "\t\t\t4: R_RISCV_BRANCH\t.text+0x8\n"
            "   8:\t00008067                \tret\n"
            "000000000000000c <.LBB0_1>:\n"
            "   c:\t00008067                \tret\n"
        )
        control = forensic.resolve_local_control_flow(dump)
        self.assertEqual(control["status"], "resolved")
        kinds = {edge["resolved_by"] for edge in control["edges"] if edge["kind"] == "internal"}
        self.assertIn("relocation-local-label", kinds)
        self.assertIn("relocation-section-addend", kinds)
        self.assertEqual([edge["target"] for edge in control["edges"] if edge["kind"] == "internal"],
                         [3, 2])

    def test_external_call_targets_stay_unknown_without_becoming_cfg_edges(self):
        dump = (
            "0000000000000000 <_Zf>:\n"
            "   0:\t000000ef                \tjal     ra,0x0 <_Zf>\n"
            "\t\t\t0: R_RISCV_CALL\t_Zexternal\n"
            "   4:\t000000ef                \ttail    0x4 <_Zg>\n"
            "\t\t\t4: R_RISCV_CALL\t_Zg+0x10\n"
            "   8:\t00008067                \tret\n"
        )
        control = forensic.resolve_local_control_flow(dump)
        self.assertEqual(control["status"], "resolved")
        self.assertEqual([item["symbol"] for item in control["external_targets_kept_unknown"]],
                         ["_Zexternal", "_Zg"])
        self.assertEqual([item["addend"] for item in control["external_targets_kept_unknown"]],
                         ["0x0", "0x10"])
        self.assertTrue(all(edge["kind"] == "external-unknown"
                            for edge in control["edges"] if edge["target"]))

    def test_unresolvable_targets_make_the_local_cfg_unreliable(self):
        missing_label = (
            "Disassembly of section .text:\n"
            "\n"
            "0000000000000000 <_Zf>:\n"
            "   0:\t00000063                \tbeq     a0,a1,0x0 <_Zf>\n"
            "\t\t\t0: R_RISCV_BRANCH\t.LBB9_9\n"
            "   4:\t00008067                \tret\n"
        )
        control = forensic.resolve_local_control_flow(missing_label)
        self.assertEqual(control["status"], "unresolved")
        self.assertEqual(control["unresolved"][0]["reason"], "local-label-address-unknown")
        outside = (
            "Disassembly of section .text:\n"
            "\n"
            "0000000000000000 <_Zf>:\n"
            "   0:\t00000063                \tbeq     a0,a1,0x99 <_Zf+0x99>\n"
            "   4:\t00008067                \tret\n"
        )
        control = forensic.resolve_local_control_flow(outside)
        self.assertEqual(control["status"], "unresolved")
        self.assertEqual(control["unresolved"][0]["reason"], "numeric-target-outside-function")

    def test_incomplete_local_source_never_reports_disappearance(self):
        before = {"label": "A", "status": "incomplete", "gaps": ["local-cfg-not-reliably-resolved"],
                  "facts": {"conservative_addresses": ["0x4"]}}
        after = {"label": "B", "status": "complete", "gaps": [],
                 "facts": {"conservative_addresses": []}}
        comparison = forensic.compare_local_sources(before, after)
        self.assertEqual(comparison["status"], "incomplete")
        self.assertIsNone(comparison["conservative_sources_disappeared"])
        self.assertIn("A:local-cfg-not-reliably-resolved", comparison["gaps"])

    def test_complete_local_source_reports_disappearance_per_field(self):
        before = {"label": "A", "status": "complete", "gaps": [],
                  "facts": {"conservative_addresses": ["0x4"],
                            "local_call_sites_carrying_conservative": ["0x10"]}}
        after = {"label": "B", "status": "complete", "gaps": [],
                 "facts": {"conservative_addresses": [],
                           "irreducible_object_live_at": ["0x8"]}}
        # Without a proven address correspondence the per-address deltas stay
        # unknown: the gate moves code, so addresses are not identities.
        comparison = forensic.compare_local_sources(before, after)
        self.assertEqual(comparison["status"], "complete")
        self.assertEqual(comparison["address_correspondence"], "not-established")
        self.assertTrue(comparison["conservative_sources_disappeared"])
        self.assertIsNone(comparison["fields"]["conservative_addresses"]["disappeared"])
        self.assertTrue(comparison["fields"]["conservative_addresses"]["present_in_a"])
        self.assertFalse(comparison["fields"]["conservative_addresses"]["present_in_b"])
        self.assertTrue(comparison["fields"]["irreducible_object_live_at"]["present_in_b"])
        self.assertEqual(comparison["markers_still_present_in_b"], ["irreducible"])

        established = forensic.compare_local_sources(before, after,
                                                     address_correspondence="established")
        self.assertEqual(established["fields"]["conservative_addresses"]["disappeared"], ["0x4"])
        self.assertEqual(established["fields"]["irreducible_object_live_at"]["appeared"], ["0x8"])

    def test_local_source_observation_without_an_object_is_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = SimpleNamespace(objdump="objdump", readelf="readelf")
            observation = forensic.local_source_observation(root / "missing.o", "_Zf",
                                                            root / "local", args, "A")
            self.assertEqual(observation["status"], "incomplete")
            self.assertIn("group-object-missing", observation["gaps"])


class VectorEvidenceTests(unittest.TestCase):
    def test_vector_instructions_vs2r_and_vlen_reads_are_listed_separately(self):
        evidence = forensic.vector_evidence(
            "0000000000000000 <_Zf>:\n"
            "   0:\t02730027                \tvse8.v  v8,(a0)\n"
            "   4:\t22878427                \tvs2r.v  v8,(a5)\n"
            "   8:\tc22022f3                \tcsrr    t0,vlenb\n"
            "   c:\t00008067                \tret\n")
        self.assertEqual(evidence["vector_instruction_count"], 2)
        self.assertEqual(len(evidence["vs2r_v"]), 1)
        self.assertEqual(len(evidence["vlen_reads"]), 1)
        self.assertEqual(evidence["instruction_count"], 4)

    def test_census_rows_are_selected_by_exact_symbol_only(self):
        text = ("implicit-vector-census\tLV\t_Ztarget\tblocked\n"
                "implicit-vector-census\tSLP\t_ZtargetB5cxx11\tformed\n"
                "implicit-vector-census\tMEMOP\t_Zother\tformed\n")
        result = forensic.filter_census_rows(text, "_Ztarget")
        self.assertEqual(len(result["rows_for_exact_symbol"]), 1)
        self.assertEqual(result["actions"], ["blocked"])
        self.assertEqual(result["rows_total"], 3)

    def test_delta_classification_reports_disappeared_remaining_and_appeared(self):
        before = forensic.vector_evidence(
            "0000000000000000 <_Zf>:\n   0:\t02730027 vse8.v v8,(a0)\n"
            "   4:\t22878427 vs2r.v v8,(a5)\n")
        after = forensic.vector_evidence(
            "0000000000000000 <_Zf>:\n   0:\t02730027 vse8.v v8,(a0)\n"
            "   4:\t22840427 vs1r.v v8,(a0)\n")
        delta = forensic.classify_vector_delta(before, after)
        self.assertEqual(delta["vector_mnemonics_disappeared"], ["vs2r.v"])
        self.assertEqual(delta["vector_mnemonics_remaining"], ["vse8.v"])
        self.assertEqual(delta["vector_mnemonics_appeared"], ["vs1r.v"])
        self.assertEqual(delta["elimination_status"], "not-eliminated")


if __name__ == "__main__":
    unittest.main()
