"""No callback name allowlist: actual bodies, ABI returns, and immutable data."""
from pathlib import Path
import copy
import hashlib
import io
import json
from types import SimpleNamespace
import struct
import tempfile
import time
import unittest

from chimera.preprocess.offline.analysis.core.data_model import Function, Instruction
from chimera.preprocess.offline.analysis.safety.native_call_closure import (
    ClosureRefusal, NativeCallClosure,
)
from chimera.preprocess.offline.analysis.safety.native_call_binding import NativeClosureEnvironment
from test_external_scalar_leaf import dynamic_elf as _dynamic_elf


def dynamic_elf(path, **options):
    result = _dynamic_elf(path, **options)
    raw = bytearray(path.read_bytes())
    struct.pack_into('<I', raw, 48, 5)  # RV64 compressed + LP64D.
    from elftools.elf.elffile import ELFFile
    elf = ELFFile(io.BytesIO(raw))
    section = elf.get_section_by_name('.text') or elf.get_section_by_name('.plt')
    struct.pack_into('<Q', raw, 32, len(raw))
    struct.pack_into('<H', raw, 56, 1)
    raw.extend(struct.pack('<IIQQQQQQ', 1, 5, section['sh_offset'], section['sh_addr'],
                           section['sh_addr'], section['sh_size'], section['sh_size'], 2))
    path.write_bytes(raw)
    return result


def body(specs, start=0x2000):
    insts, data = [], bytearray()
    for op, args, machine in specs:
        raw = bytes.fromhex(machine)[::-1]
        insts.append(Instruction(start+len(data), len(raw), op, tuple(args),
                                 op+' '+','.join(args), machine_code=machine))
        data.extend(raw)
    return Function('anonymous', start, insts), bytes(data)


RET = ('ret', (), '8082')
PUSH = ('addi', ('sp', 'sp', '-16'), '1141')
POP = ('addi', ('sp', 'sp', '16'), '0141')
SAVE = ('sd', ('ra', '8(sp)'), 'e406')
RESTORE = ('ld', ('ra', '8(sp)'), '60a2')


class Environment:
    def __init__(self, bodies, *, immutable=False):
        self.bodies, self.immutable = bodies, immutable

    def body(self, key):
        if key not in self.bodies:
            raise ClosureRefusal('missing-body')
        return self.bodies[key]

    def target(self, key, address):
        result = key[0], address
        if result not in self.bodies:
            raise ClosureRefusal('missing-target')
        return result

    def load(self, key, address, size):
        return ('immutable', *address[1:], size) if self.immutable else None

    def tls_write(self, address, size):
        return False


class ClosureTests(unittest.TestCase):
    def prove(self, specs, **kwargs):
        return NativeCallClosure(Environment({('lib', 0x2000): body(specs)}, **kwargs)).prove(('lib', 0x2000))

    def test_leaf_has_no_name_requirement(self):
        self.assertEqual(self.prove([RET])['size'], 2)

    def test_fixed_frame_and_preserved_return(self):
        self.prove([PUSH, SAVE, RESTORE, POP, RET])

    def test_indirect_callback_vector_csr_syscall_and_unknown_are_open(self):
        for insn in [('jalr', ('a0',), '9502'),
                     ('vadd.vv', ('v1', 'v2', 'v3'), '003100d7'),
                     ('csrr', ('a0', 'vlenb'), 'c2202573'),
                     ('ecall', (), '00000073'), ('unimp', (), '0000')]:
            with self.subTest(op=insn[0]), self.assertRaises(ClosureRefusal):
                self.prove([insn, RET])

    def test_return_cannot_be_replaced_by_argument(self):
        with self.assertRaises(ClosureRefusal):
            self.prove([('mv', ('ra', 'a0'), '80aa'), RET])

    def test_partial_return_address_save_does_not_preserve_rv64(self):
        with self.assertRaises(ClosureRefusal):
            self.prove([PUSH, ('sw', ('ra', '8(sp)'), '00112423'),
                        ('lw', ('ra', '8(sp)'), '00812083'), POP, RET])

    def test_narrow_fp_load_nan_boxing_cannot_hide_a_callback(self):
        for load, store, load_word, store_word in [
                ('flh', 'sh', '00011007', '00b11023'),
                ('flw', 'sw', '00012007', '00b12023')]:
            with self.subTest(load=load), self.assertRaises(ClosureRefusal):
                self.prove([PUSH, ('li', ('a1', '1'), '4585'),
                    (store, ('a1', '0(sp)'), store_word),
                    (load, ('ft0', '0(sp)'), load_word),
                    ('fmv.x.d', ('a0', 'ft0'), 'e2000553'),
                    ('bne', ('a0', 'a1', '2018'), '00b51463'),
                    POP, RET, ('jalr', ('a0',), '9502'), RET])

    def test_unknown_pointer_write_cannot_modify_caller_frame(self):
        with self.assertRaises(ClosureRefusal):
            self.prove([('sd', ('a1', '0(a0)'), '00b53023'), RET])

    def test_truncated_and_changed_machine_bytes_are_not_proofs(self):
        function, code = body([RET])
        for bad in (b'\0\0', code+b'\0\0'):
            with self.subTest(bad=bad), self.assertRaises(ClosureRefusal):
                NativeCallClosure(Environment({('lib', 0x2000): (function, bad)})).prove(('lib', 0x2000))

    def test_call_closure_checks_child_not_just_first_function(self):
        caller = body([PUSH, SAVE, ('jal', ('ra', '3000'), '000000ef'), RESTORE, POP, RET])
        for child, good in [(body([RET], 0x3000), True),
                            (body([('jalr', ('a0',), '9502'), RET], 0x3000), False)]:
            solver = NativeCallClosure(Environment({('lib', 0x2000): caller, ('lib', 0x3000): child}))
            if good:
                self.assertEqual(solver.prove(('lib', 0x2000))['callees'], (('lib', 0x3000),))
            else:
                with self.assertRaises(ClosureRefusal):solver.prove(('lib', 0x2000))

    def test_unbalanced_tail_and_recursion_stay_open(self):
        for specs in ([PUSH, ('j', ('3000',), 'a001')], [('j', ('2000',), 'a001')]):
            bodies = {('lib', 0x2000): body(specs), ('lib', 0x3000): body([RET], 0x3000)}
            with self.assertRaises(ClosureRefusal):NativeCallClosure(Environment(bodies)).prove(('lib', 0x2000))

    def test_immutable_canary_can_prune_callback_but_mutable_load_cannot(self):
        specs = [('auipc', ('a0', '0'), '00000517'),
                 ('ld', ('a1', '0(a0)'), '610c'), ('ld', ('a2', '0(a0)'), '6110'),
                 ('xor', ('a1', 'a1', 'a2'), '8db1'),
                 ('bnez', ('a1', '200e'), 'e199'), RET,
                 ('jalr', ('a0',), '9502'), RET]
        self.assertTrue(self.prove(specs, immutable=True)['pruned_edges'])
        with self.assertRaises(ClosureRefusal):self.prove(specs, immutable=False)

    def test_different_load_extensions_cannot_prune_callback(self):
        specs = [('auipc', ('a0', '0'), '00000517'),
                 ('lb', ('a1', '0(a0)'), '00050583'), ('lbu', ('a2', '0(a0)'), '00054603'),
                 ('xor', ('a1', 'a1', 'a2'), '8db1'),
                 ('bnez', ('a1', '2012'), 'e199'), RET,
                 ('jalr', ('a0',), '9502'), RET]
        with self.assertRaises(ClosureRefusal):self.prove(specs, immutable=True)

    def test_resource_budgets_cannot_release_boundary(self):
        root = body([PUSH, SAVE, ('jal', ('ra', '3000'), '000000ef'), RESTORE, POP, RET])
        env = Environment({('lib', 0x2000): root, ('lib', 0x3000): body([RET], 0x3000)})
        for options in ({'maximum_functions': 1}, {'maximum_code_bytes': 1}):
            with self.subTest(options=options), self.assertRaises(ClosureRefusal):
                NativeCallClosure(env, **options).prove(('lib', 0x2000))

    def test_loop_join_reopens_a_previously_pruned_edge(self):
        prefix = [('li', ('t0', '0'), '4281'), ('beqz', ('t0', '2008'), '00028363')]
        suffix = [('mv', ('t0', 'a0'), '82aa'), ('bnez', ('a1', '2002'), 'fe059ce3'), RET]
        with self.assertRaises(ClosureRefusal):
            self.prove([*prefix, ('jalr', ('a0',), '9502'), *suffix])
        result = self.prove([*prefix, ('nop', (), '0001'), *suffix])
        self.assertFalse(result['pruned_edges'])


class ElfClosureBindingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.main, self.provider = self.root/'app', self.root/'unlisted-library.so'
        self.name = 'ordinary_unlisted_function'
        dynamic_elf(self.main, symbol_name=self.name)
        dynamic_elf(self.provider, provider=True, symbol_name=self.name)
        # Replace its same-size scalar store with nop: a no-write ABI leaf.
        original = self.provider.read_bytes()
        original = original.replace(bytes.fromhex('00b50023')[::-1], bytes.fromhex('00000013')[::-1], 1)
        self.provider.write_bytes(original)
        self.function, self.code = body([('nop', (), '00000013'), RET])
        self.modules = [SimpleNamespace(module_id='app', selected_path=self.main),
                        SimpleNamespace(module_id='provider', selected_path=self.provider)]

    def environment(self):
        return NativeClosureEnvironment(self.main, self.modules, 'unused',
            disassemble=lambda path, symbol, start, size, tool: self.function)

    def test_arbitrary_name_requires_actual_machine_proof(self):
        proof = self.environment().prove_root(0x1000)
        self.assertEqual(proof['symbol'], self.name)
        self.assertEqual(proof['provider_module'], 'provider')
        self.assertEqual(proof['status'], 'verified-native-scalar-call-closure')

    def test_ifunc_and_interposed_provider_are_rejected(self):
        dynamic_elf(self.provider, provider=True, ifunc=True, symbol_name=self.name)
        with self.assertRaises(ClosureRefusal):self.environment().prove_root(0x1000)
        dynamic_elf(self.provider, provider=True, symbol_name=self.name)
        other = self.root/'other.so';dynamic_elf(other, provider=True, symbol_name=self.name)
        self.modules.append(SimpleNamespace(module_id='other', selected_path=other))
        with self.assertRaises(ClosureRefusal):self.environment().prove_root(0x1000)

    def test_bad_plt_version_and_loader_hooks_are_rejected(self):
        for options in ({'bad_plt': True}, {'version': 'OTHER'}, {'dynamic_tag': 0x6ffffefc}):
            dynamic_elf(self.main, symbol_name=self.name, **options)
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.environment().prove_root(0x1000)

    def test_other_float_abis_cannot_reuse_64_bit_fp_preservation(self):
        raw = bytearray(self.provider.read_bytes())
        struct.pack_into('<I', raw, 48, 7)  # LP64Q has wider preserved FP state.
        self.provider.write_bytes(raw)
        with self.assertRaisesRegex(ClosureRefusal, 'lp64d'):
            self.environment().prove_root(0x1000)

    def test_writable_or_differently_mapped_native_code_is_not_a_proof(self):
        original = self.provider.read_bytes()
        phoff = struct.unpack_from('<Q', original, 32)[0]
        for offset, value, fmt in [(phoff+4, 7, '<I'), (phoff+8, 0, '<Q')]:
            raw = bytearray(original);struct.pack_into(fmt, raw, offset, value)
            self.provider.write_bytes(raw)
            with self.subTest(offset=offset), self.assertRaises(ClosureRefusal):
                self.environment().prove_root(0x1000)

    def test_tls_symbol_must_fit_the_actual_loader_tls_section(self):
        env = self.environment();env._initialize()
        definition = env.snapshots['provider'].definitions[self.name][0]
        definition.update(type='STT_TLS', value=40, size=4)
        section = dict(sh_flags=0x400, sh_addr=0x1028, sh_size=88)
        segment = dict(p_type='PT_TLS', p_vaddr=0x1000, p_memsz=128)
        env.snapshots['provider'].elf = SimpleNamespace(
            get_section=lambda index: section, iter_segments=lambda: iter([segment]))
        self.assertEqual(env.resolve_symbol(self.name, None, 'STT_TLS')[0], 'provider')
        for field, value in [('sh_flags', 0), ('sh_size', 1), ('sh_addr', 0x2000)]:
            previous = section[field];section[field] = value
            with self.subTest(field=field), self.assertRaises(ClosureRefusal):
                env.resolve_symbol(self.name, None, 'STT_TLS')
            section[field] = previous
        definition['value'] = 127
        with self.assertRaises(ClosureRefusal):env.resolve_symbol(self.name, None, 'STT_TLS')

    def launch_fixture(self):
        from chimera.preprocess.offline.analysis.safety.external_leaf import file_sha256
        proof = json.loads(json.dumps(self.environment().prove_root(0x1000)))
        modules = [SimpleNamespace(module_id=m.module_id, runtime_name=m.selected_path.name,
                    role='main' if m.module_id == 'app' else 'dependency',
                    sha256=file_sha256(m.selected_path)) for m in self.modules]
        document = dict(format='chimera-external-call-contracts-v3',
                        elf_sha256=modules[0].sha256, proofs=[], rejections=[],
                        no_callback_interfaces=[], native_no_callback_proofs=[proof],
                        closed_calls={'12292': [0x1000]})
        artifact = SimpleNamespace(capability='external-scalar-leaf-contracts',
            owner_kind='module', owner_id='app', abi=1, representation='json',
            path='native-proof.json')
        manifest = SimpleNamespace(modules=modules, artifacts=[artifact])
        resolved = {m.module_id: m.selected_path for m in self.modules}

        def validate():
            from chimera.runtime.launcher.external_leaf import validate_leaf_launch
            from chimera.runtime.artifacts.validate.chimera.validate.capabilities import verify_external_leaf_json
            path = self.root/artifact.path
            path.write_text(json.dumps(document), encoding='utf-8')
            artifact.sha256 = file_sha256(path)
            verify_external_leaf_json(path, artifact, manifest, None)
            return validate_leaf_launch(self.root, manifest, resolved,
                environment={}, system_preload=self.root/'no-preload')
        return document, resolved, modules, validate

    def test_serialized_native_proof_is_rebound_at_launch(self):
        _document, _resolved, _modules, validate = self.launch_fixture()
        self.assertTrue(validate())

    def test_replaced_provider_cannot_reuse_a_serialized_native_proof(self):
        _document, _resolved, modules, validate = self.launch_fixture()
        self.assertTrue(validate())
        raw = bytearray(self.provider.read_bytes())
        # Change even a non-code byte: the proof binds the complete provider,
        # not only the root symbol or its recorded instruction range.
        raw[8] ^= 1
        self.provider.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, 'module identity changed'):
            validate()
        # Updating the Manifest alone must not make an old proof current.
        modules[1].sha256 = hashlib.sha256(raw).hexdigest()
        with self.assertRaisesRegex(ValueError, 'module identities differ'):
            validate()

    def test_native_proof_graph_code_and_import_tampering_are_rejected(self):
        document, _resolved, _modules, validate = self.launch_fixture()
        original = copy.deepcopy(document)
        for field, value in [('code_sha256', '0'*64), ('callees', [['provider', 0x9999]])]:
            document.clear(); document.update(copy.deepcopy(original))
            document['native_no_callback_proofs'][0]['functions'][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):validate()
        document.clear(); document.update(original)
        document['native_no_callback_proofs'][0]['got'] += 8
        with self.assertRaises(ValueError):validate()

    def test_native_proof_does_not_accept_a_runtime_interposer(self):
        document, resolved, modules, validate = self.launch_fixture()
        other = self.root/'interposer.so'; dynamic_elf(other, provider=True, symbol_name=self.name)
        resolved['other'] = other
        modules.append(SimpleNamespace(module_id='other', runtime_name=other.name,
                       role='dependency', sha256=hashlib.sha256(other.read_bytes()).hexdigest()))
        # Even a document whose module hash map includes the interposer must
        # recheck the actual process-wide dynamic definition, not just hashes.
        document['native_no_callback_proofs'][0]['modules']['other'] = modules[-1].sha256
        with self.assertRaisesRegex(ValueError, 'interposed'):validate()

    def lazy_result(self):
        from chimera.check_elf import collect_diagnostics
        from chimera.preprocess.offline.analysis.safety.classifier import classify_liveness
        from chimera.preprocess.offline.analysis.safety.external_leaf import ExternalLeafBindings
        from chimera.preprocess.offline.analysis.safety.native_call_binding import NativeClosureBindings
        from chimera.preprocess.offline.analysis.safety.stack_liveness.model import ChimeraMetadata
        provider = NativeClosureBindings(self.main, self.modules, 'unused')
        provider.environment.disassemble = self.environment().disassemble
        bindings = ExternalLeafBindings(native_provider=provider)
        dump = ('0000000000003000 <caller>:\n'
                ' 3000:\t00000013\tcsrr\ts4,vlenb\n'
                ' 3004:\t00000013\tjal\tra,1000 <ordinary_unlisted_function@plt>\n'
                ' 3008:\t00000013\tadd\tt0,s4,zero\n'
                ' 300c:\t00000013\tret\n\n'
                '0000000000001000 <ordinary_unlisted_function@plt>:\n')
        return collect_diagnostics(self.main, objdump_cmd='unused', min_vlen_bits=256,
            dump_text=dump, strategy='gate', metadata=ChimeraMetadata.empty(),
            external_leaf_bindings=bindings)

    def test_lazy_boundary_closure_keeps_caller_width_state_unsafe(self):
        from chimera.preprocess.offline.analysis.safety.classifier import classify_liveness
        result = self.lazy_result()
        self.assertEqual(result.analysis.stack.closed_external_calls, {0x3004: (0x1000,)})
        self.assertFalse(any(item.diagnostic_code == 'active-external-call' for item in result.findings))
        safety = classify_liveness(result.analysis.program, SimpleNamespace(by_function={}), result.analysis.stack)
        self.assertFalse(safety.records[0x3004].safe)
        self.assertIn('live_vlen_scalar_data', safety.records[0x3004].reasons)

    def test_actual_callback_refusal_keeps_the_original_finding(self):
        self.function, _code = body([('jalr', ('a0',), '9502'), ('nop', (), '0001'), RET])
        raw = self.provider.read_bytes().replace(bytes.fromhex('13000000'), bytes.fromhex('02950100'), 1)
        self.provider.write_bytes(raw)
        result = self.lazy_result()
        self.assertFalse(result.analysis.stack.closed_external_calls)
        self.assertTrue(any(item.diagnostic_code == 'active-external-call' for item in result.findings))
        self.assertFalse(result.analysis.stack.external_native_call_proofs)
        self.assertTrue(result.analysis.stack.external_native_call_rejections)

    def test_fresh_analysis_reopens_a_replaced_native_provider(self):
        first = self.lazy_result()
        self.assertTrue(first.analysis.stack.closed_external_calls)
        old_proofs = copy.deepcopy(first.analysis.stack.external_native_call_proofs)
        self.function, _code = body([('jalr', ('a0',), '9502'), ('nop', (), '0001'), RET])
        raw = self.provider.read_bytes().replace(bytes.fromhex('13000000'),
                                                 bytes.fromhex('02950100'), 1)
        self.provider.write_bytes(raw)
        second = self.lazy_result()
        self.assertFalse(second.analysis.stack.closed_external_calls)
        self.assertTrue(any(item.diagnostic_code == 'active-external-call'
                            for item in second.findings))
        self.assertFalse(second.analysis.stack.external_native_call_proofs)
        self.assertTrue(second.analysis.stack.external_native_call_rejections)
        self.assertEqual(first.analysis.stack.external_native_call_proofs, old_proofs)


if __name__ == '__main__':unittest.main()
