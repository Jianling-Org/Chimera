"""An external leaf proof closes a boundary, never the caller's live frame."""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import tempfile
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from chimera.check_elf import collect_diagnostics, safety_binary_check_request
from chimera.preprocess.offline.analysis.arch.riscv.rvv import RvvServices
from chimera.preprocess.offline.analysis.core.data_model import Function, Instruction
from chimera.preprocess.offline.analysis.safety.classifier import classify_liveness
from chimera.preprocess.offline.analysis.safety.external_leaf import (
    ExternalLeafBindings, normalize_leaf_contracts, verify_scalar_leaf,
    bind_external_scalar_leaves,
)
from chimera.preprocess.offline.analysis.safety.stack_liveness.model import ChimeraMetadata
from chimera.preprocess.offline.analysis.safety import external_leaf_binding as binding


def leaf(specs):
    address = 0x2000
    insts, code = [], b""
    for op, args, word in specs:
        data = bytes.fromhex(word)[::-1]
        insts.append(Instruction(address, len(data), op, args,
                                 f"{address:x}: {word} {op} {','.join(args)}", machine_code=word))
        address += len(data)
        code += data
    return Function("memset", 0x2000, insts), code


class LeafBodyTests(unittest.TestCase):
    def verify(self, specs):
        function, code = leaf(specs)
        return verify_scalar_leaf(function, len(code), code)

    def test_closed_scalar_loop_with_normal_return(self):
        self.assertEqual(self.verify([
            ("sb", ["a1", "0(a0)"], "00b50023"),
            ("addi", ["a0", "a0", "1"], "0505"),
            ("bnez", ["a2", "2000 <memset>"], "fe061de3"),
            ("ret", [], "8082"),
        ]), ())

    def test_callback_call_syscall_unknown_vector_csr_and_return_change_are_rejected(self):
        cases = [
            ("jalr", ["a0"], "9502"), ("jal", ["ra", "3000"], "000000ef"),
            ("ecall", [], "00000073"), ("unimp", [], "0000"),
            ("vadd.vv", ["v1", "v2", "v3"], "003100d7"),
            ("csrr", ["a0", "vlenb"], "c2202573"),
            ("mv", ["ra", "a0"], "80aa"), ("addi", ["sp", "sp", "-16"], "1141"),
            ("jr", ["t0"], "8282"), ("j", ["3000 <other>"], "a001"),
        ]
        for item in cases:
            with self.subTest(op=item[0], args=item[1]):
                self.assertTrue(self.verify([item, ("ret", [], "8082")]))

    def test_missing_bytes_wrong_bytes_and_branch_into_instruction_are_rejected(self):
        function, code = leaf([("addi", ["a0", "a0", "1"], "0505"), ("ret", [], "8082")])
        self.assertTrue(verify_scalar_leaf(function, len(code) + 2, code + b"\0\0"))
        self.assertTrue(verify_scalar_leaf(function, len(code), b"\0" * len(code)))
        self.assertTrue(self.verify([("beqz", ["a0", "2001"], "c101"), ("ret", [], "8082")]))

    def test_fallthrough_outside_body_is_not_closed(self):
        self.assertTrue(self.verify([("addi", ["a0", "a0", "1"], "0505")]))


CONTRACT = {"symbol": "memset", "library": "libc.so.6", "sha256": "a" * 64}


class RequestTests(unittest.TestCase):
    def test_requests_are_content_pinned_and_part_of_v32_fingerprint(self):
        params = {"min_vlen_bits": 256, "compiler_metadata": [],
                  "external_scalar_leaf_contracts": [CONTRACT]}
        request = safety_binary_check_request(params)
        self.assertEqual(request.version, 32)
        self.assertEqual(request.parameters["external_scalar_leaf_contracts"],
                         normalize_leaf_contracts([CONTRACT]))
        changed = dict(CONTRACT, sha256="b" * 64)
        self.assertNotEqual(request.identity, safety_binary_check_request(
            dict(params, external_scalar_leaf_contracts=[changed])).identity)

    def test_names_paths_duplicate_requests_and_unpinned_hashes_are_not_contracts(self):
        for contracts in ([{"symbol": "memset"}], [dict(CONTRACT, sha256="latest")],
                          [dict(CONTRACT, library="../libc.so.6")],
                          [dict(CONTRACT, symbol="memset@plt")], [CONTRACT, CONTRACT],
                          [dict(CONTRACT, symbol="memcpy")]):
            with self.subTest(contracts=contracts), self.assertRaises(ValueError):
                normalize_leaf_contracts(contracts)


def dynamic_elf(path, *, provider=False, ifunc=False, relocation_type=5, bad_plt=False,
                version=None, hidden=False, absolute=False, dynamic_tag=None,
                symbol_binding=1, symbol_name="memset"):
    """Real dynsym and JUMP_SLOT sections, not a name-based binder mock."""
    from elf_fixture import EHDR, SHDR
    instructions, body = leaf([("sb", ["a1", "0(a0)"], "00b50023"), ("ret", [], "8082")])
    stub = struct.pack("<IIII", 0x3e17, (16 << 20) | 0xe3e03, 0xe0367, 0x13)
    if bad_plt:
        stub = b"\0" * 16
    symbol = struct.pack("<IBBHQQ", 1, (symbol_binding << 4) | (10 if ifunc else 2), 0,
                         (0xfff1 if absolute else 1) if provider else 0, 0x2000 if provider else 0,
                         len(body) if provider else 0)
    parts = [(".text" if provider else ".plt", 1, 6, 0x2000 if provider else 0x1000,
              body if provider else stub, 0, 0),
             (".dynstr", 3, 0, 0, b"\0" + symbol_name.encode() + b"\0", 0, 0),
             (".dynsym", 11, 0, 0, b"\0" * 24 + symbol, 2, 24)]
    if not provider:
        parts.append((".rela.plt", 4, 0, 0, struct.pack("<QQq", 0x4010,
                       (1 << 32) | relocation_type, 0), 3, 24))
    if version is not None:
        name_offset = len(parts[1][4])
        parts[1] = (*parts[1][:4], parts[1][4] + version.encode() + b"\0", 0, 0)
        parts.append((".gnu.version", 0x6fffffff, 0, 0,
                      struct.pack("<HH", 0, 2 | (0x8000 if hidden else 0)), 3, 2))
        if provider:
            data = struct.pack("<HHHHIII", 1, 0, 2, 1, 0, 20, 0)
            data += struct.pack("<II", name_offset, 0)
            parts.append((".gnu.version_d", 0x6ffffffd, 0, 0, data, 2, 0))
        else:
            data = struct.pack("<HHIII", 1, 1, name_offset, 16, 0)
            data += struct.pack("<IHHII", 0, 0, 2, name_offset, 0)
            parts.append((".gnu.version_r", 0x6ffffffe, 0, 0, data, 2, 0))
    if dynamic_tag is not None:
        parts.append((".dynamic", 6, 0, 0,
                      struct.pack("<QQQQ", dynamic_tag, 1, 0, 0), 2, 16))
    strings, offsets = b"\0", {}
    for name in [part[0] for part in parts] + [".shstrtab"]:
        offsets[name] = len(strings)
        strings += name.encode() + b"\0"
    parts.append((".shstrtab", 3, 0, 0, strings, 0, 0))
    image, headers = bytearray(64), [b"\0" * SHDR.size]
    for name, kind, flags, address, content, link, entsize in parts:
        offset = len(image)
        image.extend(content)
        headers.append(SHDR.pack(offsets[name], kind, flags, address, offset,
                                 len(content), link, int(name in {".gnu.version_d", ".gnu.version_r"}), 1, entsize))
    shoff = len(image)
    image.extend(b"".join(headers))
    image[:64] = EHDR.pack(b"\x7fELF\x02\x01\x01" + b"\0" * 9, 3, 243,
        1, 0, 0, shoff, 0, 64, 56, 0, 64, len(headers), len(headers) - 1)
    path.write_bytes(image)
    return instructions


class ElfBindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.main, self.provider = self.root / "app", self.root / "libc.so.6"
        dynamic_elf(self.main)
        self.body = dynamic_elf(self.provider, provider=True)
        from chimera.preprocess.offline.analysis.core.data_model import Program
        self.program = Program([], [Function("memset@plt", 0x1000, [], is_external_trampoline=True)], [], {})
        self.modules = [SimpleNamespace(module_id="app", selected_path=self.main, is_scalar=False),
                        SimpleNamespace(module_id="libc_so_6", selected_path=self.provider, is_scalar=True)]
        self.contract = dict(CONTRACT, sha256=sha256(self.provider.read_bytes()).hexdigest())

    def bind(self):
        with patch.object(binding, "disassemble_leaf",
                   return_value=self.body):
            return bind_external_scalar_leaves(self.main, self.program, self.modules,
                                                [self.contract], objdump="objdump")

    def test_real_plt_and_relocation_bind_the_unique_pinned_implementation(self):
        bound = self.bind()
        self.assertEqual(bound.closed_targets, frozenset({0x1000}))
        self.assertEqual(bound.rejections, ())
        self.assertEqual(bound.proofs[0]["provider_address"], 0x2000)
        self.assertEqual(bound.proofs[0]["size"], 6)

    def test_same_name_unpinned_ifunc_interposed_or_non_scalar_never_closes(self):
        for mode in ("hash", "ifunc", "interpose", "non-scalar"):
            with self.subTest(mode=mode):
                self.setUp()
                if mode == "hash":
                    self.contract["sha256"] = "b" * 64
                elif mode == "ifunc":
                    dynamic_elf(self.provider, provider=True, ifunc=True)
                    self.contract["sha256"] = sha256(self.provider.read_bytes()).hexdigest()
                elif mode == "interpose":
                    replacement = self.root / "shim.so"
                    dynamic_elf(replacement, provider=True)
                    self.modules.append(SimpleNamespace(module_id="shim", selected_path=replacement, is_scalar=False))
                else:
                    self.modules[1].is_scalar = False
                self.assertFalse(self.bind().closed_targets)
                self.assertTrue(self.bind().rejections)

    def test_printed_name_without_correct_plt_and_jump_slot_is_not_identity(self):
        for kwargs in ({"relocation_type": 3}, {"bad_plt": True}):
            with self.subTest(kwargs=kwargs):
                dynamic_elf(self.main, **kwargs)
                self.assertFalse(self.bind().closed_targets)

    def test_leaf_failure_is_an_open_boundary(self):
        self.body.insts[0].op = "jalr"
        self.assertFalse(self.bind().closed_targets)

    def test_provider_mutation_during_analysis_invalidates_the_proof(self):
        def mutate(*args):
            self.provider.write_bytes(self.provider.read_bytes() + b"changed")
            return self.body
        with patch.object(binding, "disassemble_leaf", side_effect=mutate):
            result = bind_external_scalar_leaves(self.main, self.program, self.modules,
                                                 [self.contract], objdump="objdump")
        self.assertFalse(result.closed_targets)
        self.assertEqual(result.rejections[0]["reason"], "module-changed-during-leaf-binding")

    def test_standard_libc_memcpy_contract_accepts_ifunc_without_leaf_proof(self):
        from chimera.preprocess.offline.analysis.core.data_model import Program
        dynamic_elf(self.main, symbol_name="memcpy")
        dynamic_elf(self.provider, provider=True, ifunc=True, symbol_name="memcpy")
        self.program = Program([], [Function("memcpy@plt", 0x1000, [], is_external_trampoline=True)], [], {})
        self.modules[1].module_id = "libc_so_6"
        bound = bind_external_scalar_leaves(self.main, self.program, self.modules, (), objdump="objdump")
        self.assertEqual(bound.closed_targets, frozenset({0x1000}))
        self.assertEqual(bound.proofs, ())
        self.assertEqual(bound.interface_rejections, ())
        contract = bound.no_callback_interfaces[0]
        self.assertEqual(contract["symbol"], "memcpy")
        self.assertEqual(contract["provider_library"], "libc.so.6")
        self.assertEqual(contract["semantic_basis"], "standard-libc-memcpy-no-application-callback-v1")
        self.assertIn(contract["provider_type"], {"STT_LOOS", "STT_GNU_IFUNC"})

    def test_standard_memcpy_semantics_do_not_require_a_scalar_build_of_libc(self):
        from chimera.preprocess.offline.analysis.core.data_model import Program
        dynamic_elf(self.main, symbol_name="memcpy")
        dynamic_elf(self.provider, provider=True, ifunc=True, symbol_name="memcpy")
        self.modules[1].module_id = "libc_so_6"
        self.modules[1].is_scalar = False
        self.program = Program([], [Function("memcpy@plt", 0x1000, [], is_external_trampoline=True)], [], {})
        bound = bind_external_scalar_leaves(self.main, self.program, self.modules, (), objdump="objdump")
        self.assertEqual(bound.closed_targets, frozenset({0x1000}))
        self.assertEqual(bound.interface_rejections, ())

    def test_memcpy_import_and_provider_symbol_versions_must_match(self):
        from chimera.preprocess.offline.analysis.core.data_model import Program
        dynamic_elf(self.main, symbol_name="memcpy", version="GLIBC_2.27")
        dynamic_elf(self.provider, provider=True, ifunc=True,
                    symbol_name="memcpy", version="GLIBC_2.28")
        self.modules[1].module_id = "libc_so_6"
        self.program = Program([], [Function("memcpy@plt", 0x1000, [], is_external_trampoline=True)], [], {})
        bound = bind_external_scalar_leaves(self.main, self.program, self.modules, (), objdump="objdump")
        self.assertFalse(bound.closed_targets)
        self.assertEqual(bound.no_callback_interfaces, ())
        self.assertIn("memcpy-symbol-version-mismatch",
                      [item["reason"] for item in bound.interface_rejections])

    def test_memcpy_name_from_non_libc_or_interposed_provider_stays_open(self):
        from chimera.preprocess.offline.analysis.core.data_model import Program
        dynamic_elf(self.main, symbol_name="memcpy")
        dynamic_elf(self.provider, provider=True, ifunc=True, symbol_name="memcpy")
        self.modules[1].selected_path = self.root / "libshim.so"
        self.modules[1].selected_path.write_bytes(self.provider.read_bytes())
        self.modules[1].module_id = "libshim"
        self.program = Program([], [Function("memcpy@plt", 0x1000, [], is_external_trampoline=True)], [], {})
        bound = bind_external_scalar_leaves(self.main, self.program, self.modules, (), objdump="objdump")
        self.assertFalse(bound.closed_targets)
        self.assertEqual(bound.no_callback_interfaces, ())
        self.assertTrue(bound.interface_rejections)

    def test_memcpy_with_same_name_provider_interposition_stays_open(self):
        from chimera.preprocess.offline.analysis.core.data_model import Program
        dynamic_elf(self.main, symbol_name="memcpy")
        dynamic_elf(self.provider, provider=True, ifunc=True, symbol_name="memcpy")
        shim = self.root / "shim.so"
        dynamic_elf(shim, provider=True, ifunc=True, symbol_name="memcpy")
        self.modules.append(SimpleNamespace(module_id="shim", selected_path=shim, is_scalar=False))
        self.modules[1].module_id = "libc_so_6"
        self.program = Program([], [Function("memcpy@plt", 0x1000, [], is_external_trampoline=True)], [], {})
        bound = bind_external_scalar_leaves(self.main, self.program, self.modules, (), objdump="objdump")
        self.assertFalse(bound.closed_targets)
        self.assertTrue(bound.interface_rejections)

    def test_symbol_versions_must_match_and_the_provider_must_be_default(self):
        dynamic_elf(self.main, version="GLIBC_2.27")
        self.body = dynamic_elf(self.provider, provider=True, version="GLIBC_2.27")
        self.contract["sha256"] = sha256(self.provider.read_bytes()).hexdigest()
        self.assertEqual(self.bind().proofs[0]["version"], "GLIBC_2.27")
        for kwargs in ({"version": "GLIBC_2.28"}, {"version": "GLIBC_2.27", "hidden": True}):
            with self.subTest(kwargs=kwargs):
                self.body = dynamic_elf(self.provider, provider=True, **kwargs)
                self.contract["sha256"] = sha256(self.provider.read_bytes()).hexdigest()
                self.assertFalse(self.bind().closed_targets)

    def test_absolute_symbols_are_not_ordinary_module_relative_providers(self):
        self.body = dynamic_elf(self.provider, provider=True, absolute=True)
        self.contract["sha256"] = sha256(self.provider.read_bytes()).hexdigest()
        self.assertFalse(self.bind().closed_targets)

    def test_elf_audit_and_filter_hooks_prevent_binding(self):
        # DT_AUDIT, DT_DEPAUDIT, DT_FILTER and DT_AUXILIARY introduce a
        # loader-controlled provider or callback outside the selected graph.
        for tag in (0x6ffffefc, 0x6ffffefb, 0x7fffffff, 0x7ffffffd):
            with self.subTest(tag=tag):
                dynamic_elf(self.main, dynamic_tag=tag)
                with self.assertRaisesRegex(ValueError, "loader hook"):
                    self.bind()

    def test_gnu_unique_interposer_is_not_lost_to_pyelftools_stb_loos_alias(self):
        replacement = self.root / "unique.so"
        dynamic_elf(replacement, provider=True, symbol_binding=10)
        self.modules.append(SimpleNamespace(module_id="unique", selected_path=replacement, is_scalar=False))
        self.assertFalse(self.bind().closed_targets)


class BoundaryRetentionTests(unittest.TestCase):
    def test_uncontracted_standard_memcpy_closes_only_the_external_boundary(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            app, libc = root / "app", root / "libc.so.6"
            dynamic_elf(app, symbol_name="memcpy")
            dynamic_elf(libc, provider=True, ifunc=True, symbol_name="memcpy")
            modules = [
                SimpleNamespace(module_id="app", selected_path=app, is_scalar=False),
                SimpleNamespace(module_id="libc_so_6", selected_path=libc, is_scalar=True),
            ]
            dump = (
                "0000000000003000 <caller>:\n"
                " 3000:\t00000013\tcsrr\ts4,vlenb\n"
                " 3004:\t00000013\tjal\tra,1000 <memcpy@plt>\n"
                " 3008:\t00000013\tadd\tt0,s4,zero\n"
                " 300c:\t00000013\tret\n\n"
                "0000000000001000 <memcpy@plt>:\n")
            result = collect_diagnostics(app, objdump_cmd="objdump", min_vlen_bits=256,
                dump_text=dump, strategy="gate", metadata=ChimeraMetadata.empty(),
                external_modules=modules)
            self.assertEqual(result.analysis.stack.closed_external_calls, {0x3004: (0x1000,)})
            self.assertEqual(result.analysis.stack.external_leaf_proofs, ())
            self.assertEqual(result.analysis.stack.external_no_callback_interfaces[0]["symbol"], "memcpy")
            self.assertFalse(any(item.diagnostic_code == "active-external-call"
                                 for item in result.findings))
            safety = classify_liveness(result.analysis.program,
                SimpleNamespace(by_function={}), result.analysis.stack)
            self.assertFalse(safety.records[0x3004].safe)
            self.assertIn("live_vlen_scalar_data", safety.records[0x3004].reasons)

    def test_leaf_summary_does_not_authorize_a_tail_or_custom_link_return(self):
        from test_external_call_gate import _call, _function
        from chimera.preprocess.offline.analysis.core.data_model import Program
        from chimera.preprocess.offline.analysis.safety.stack_liveness.liveness import _CallerStackContextPropagator
        from chimera.preprocess.offline.analysis.safety.stack_liveness.model import StackObjectId, StackFunctionLiveness
        for call in (_call(0x1000, 0x8000, op="j", args=["8000"]),
                     _call(0x1000, 0x8000, args=["t0", "8000"])):
            source = _function(0x1000, call)
            program = Program([], [source], [call], {0x1000: call})
            local = {0x1000: StackFunctionLiveness(0x1000,
                {0x1000: frozenset({StackObjectId("compiler", 1)})}, {})}
            stack = _CallerStackContextPropagator(RvvServices().stack_semantics).propagate(
                program, local, ChimeraMetadata.empty(), closed_external_targets=frozenset({0x8000}))
            self.assertEqual(stack.active_external_calls, (0x1000,))
            self.assertEqual(stack.closed_external_calls, {})

    def test_closed_boundary_does_not_make_the_live_vlen_frame_safe(self):
        from test_external_call_gate import _dump
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "app"
            path.write_bytes(b"\x7fELF\x02\x01\x01" + b"\0" * 24)
            proof = {"target": 0x8000, "symbol": "memset", "library": "libc.so.6",
                     "sha256": "a" * 64, "status": "verified-scalar-leaf"}
            bindings = ExternalLeafBindings((proof,), ())
            result = collect_diagnostics(path, objdump_cmd="objdump", min_vlen_bits=256,
                dump_text=_dump(inherited=False), strategy="gate", metadata=ChimeraMetadata.empty(),
                external_leaf_bindings=bindings)
            # Closing the external boundary does not make the actual live
            # frame safe. Informational cache observations are not findings.
            self.assertFalse(any(f.diagnostic_code == 'active-external-call' for f in result.findings))
            self.assertFalse(any(f.diagnostic_code == 'escaping-vlen-scalar-value' for f in result.findings))
            self.assertEqual(result.analysis.stack.closed_external_calls, {0x1008: (0x8000,)})
            vector = SimpleNamespace(by_function={})
            safety = classify_liveness(result.analysis.program, vector, result.analysis.stack)
            self.assertFalse(safety.records[0x1008].safe)
            self.assertIn("live_vlen_stack_frame", safety.records[0x1008].reasons)
            self.assertEqual(result.analysis.stack.external_leaf_proofs, (proof,))

    def test_one_closed_alternative_never_hides_an_uncovered_alternative(self):
        from test_external_call_gate import _call, _function
        from chimera.preprocess.offline.analysis.core.data_model import Program
        from chimera.preprocess.offline.analysis.safety.stack_liveness.liveness import _CallerStackContextPropagator
        from chimera.preprocess.offline.analysis.safety.stack_liveness.model import (
            CallTargetEntry, StackObjectId, StackFunctionLiveness,
        )
        source = _function(0x1000, _call(0x1000, op="jalr"))
        program = Program([], [source], source.insts, {i.addr: i for i in source.insts})
        local = {source.start: StackFunctionLiveness(source.start,
            {0x1000: frozenset({StackObjectId("compiler", 1)})}, {})}
        metadata = ChimeraMetadata(function_pointer={0x1000: CallTargetEntry(0x1000, (0x8000, 0x9000))})
        stack = _CallerStackContextPropagator(RvvServices().stack_semantics).propagate(
            program, local, metadata, closed_external_targets=frozenset({0x8000}))
        self.assertEqual(stack.warnings[0].external_targets, (0x9000,))
        self.assertEqual(stack.closed_external_calls, {0x1000: (0x8000,)})

    def test_independent_audit_uses_the_same_closed_boundary(self):
        from test_external_call_gate import _dump
        from chimera.gate_source_audit import enumerate_candidates, propagate_sources
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "app"
            path.write_bytes(b"\x7fELF\x02\x01\x01" + b"\0" * 24)
            bindings = ExternalLeafBindings(({"target": 0x8000},), ())
            analysis = collect_diagnostics(path, objdump_cmd="objdump", min_vlen_bits=256,
                dump_text=_dump(), strategy="gate", metadata=ChimeraMetadata.empty(),
                external_leaf_bindings=bindings).analysis
            candidates = enumerate_candidates(analysis.program, analysis.stack, elf_sha256="0" * 64)
            _, _, affected, _, stats = propagate_sources(analysis.program, analysis.stack,
                candidates, analysis.metadata, RvvServices().stack_semantics, elf_sha256="0" * 64)
            self.assertEqual(set(affected), set())
            self.assertEqual(stats['active_external_sites'], 0)
            self.assertEqual(stats["cross_check"]["mismatches"], [])


if __name__ == "__main__":
    unittest.main()
