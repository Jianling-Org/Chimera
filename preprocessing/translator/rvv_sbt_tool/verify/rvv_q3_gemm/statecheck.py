from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
ORIGINAL = REPO_ROOT / 'verify/rvv_bidirectional_hotspots/statecheck.py'
spec = importlib.util.spec_from_file_location('original_statecheck', ORIGINAL)
original = importlib.util.module_from_spec(spec)
spec.loader.exec_module(original)


def replace_once(text, before, after):
    count = text.count(before)
    if count != 1:
        raise ValueError(f"statecheck template expected one {before!r}, found {count}")
    return text.replace(before, after)


def wrapper(symbol, body, source_vlenb, native, command):
    text = original.wrapper(symbol, body, source_vlenb, native, command)
    if not ('(' not in command):
        raise ValueError("statecheck invariant failed: '(' not in command")
    text = replace_once(text, '    la a0, memory_data\n', '')
    scalar_seed = f'    li x5, {0x12340000 + 5 * 313}\n'
    if not (text.count(scalar_seed) == 1):
        raise ValueError('statecheck invariant failed: text.count(scalar_seed) == 1')
    text = replace_once(text, scalar_seed, f'    li x1, {0x12340000 + 313}\n' + scalar_seed)
    if command.startswith('vmacc.vx '):
        scalar_reg = command.split(',')[1].strip()
        if not (scalar_reg not in {'t0', 'x5', 'sp', 'x2', 'gp', 'x3', 'tp', 'x4'}):
            raise ValueError("statecheck invariant failed: scalar_reg not in {'t0', 'x5', 'sp', 'x2', 'gp', 'x3', 'tp', 'x4'}")
        scalar_end = f'    li x31, {0x12340000 + 31 * 313}\n'
        if not (text.count(scalar_end) == 1):
            raise ValueError('statecheck invariant failed: text.count(scalar_end) == 1')
        text = replace_once(text, scalar_end, scalar_end +
            f'    la t0, input_scalar\n    ld {scalar_reg}, 0(t0)\n'
            f'    li t0, {0x12340000 + 5 * 313}\n')
    if native:
        if not (text.count('    csrw vstart, zero\n') == 1):
            raise ValueError("statecheck invariant failed: text.count('    csrw vstart, zero\\n') == 1")
        text = replace_once(text, '    csrw vstart, zero\n',
            '    la t0, input_vstart\n    ld t0, 0(t0)\n    csrw vstart, t0\n'
            '    la t1, observed_input_vstart\n    csrr t0, vstart\n    sd t0, 0(t1)\n')
    capture = '    la t0, actual_vcsr\n    csrr t1, vcsr\n    sd t1, 0(t0)\n'
    if not (text.count(capture) == 1):
        raise ValueError('statecheck invariant failed: text.count(capture) == 1')
    text = replace_once(text, capture, capture +
        '    la t0, actual_vstart\n    csrr t1, vstart\n    sd t1, 0(t0)\n')
    if native:
        late_start = ('    la t0, simulated_cpu_state\n    li t1, 4096\n'
                      '    add t0, t0, t1\n    csrr t1, vstart\n    sd t1, 0(t0)\n')
        if not (text.count(late_start) == 1):
            raise ValueError('statecheck invariant failed: text.count(late_start) == 1')
        text = replace_once(text, late_start, late_start.replace('    csrr t1, vstart\n',
            '    la t1, actual_vstart\n    ld t1, 0(t1)\n'))
    return text


def selected_cases(direction):
    audit = json.loads((HERE / 'mac-source-pc.json').read_text())
    result = {}
    for row in audit['rows']:
        config = row['known_configurations'][0]
        key = row['command'], config['sew'], config['lmul']
        result.setdefault(key, {'source_pcs': [], 'purpose': 'actual-kernel'})['source_pcs'].append(row['source_pc'])
    extras = (
        ('vmacc.vx v8, t6, v16', 16, 1, 'semantic-t6'),
        ('vmacc.vx v8, a0, v8', 16, 1, 'same-vd-source'),
        ('vwmacc.vv v8, v9, v16', 16, 1, 'existing-overlap-layout-control'),
        ('vwmacc.vv v8, v16, v9', 16, 1, 'existing-overlap-layout-control'),
        ('vwmacc.vv v8, v9, v9', 16, 1, 'existing-overlap-layout-control'),
        ('vwmacc.vv v8, v16, v16', 16, 1, 'duplicate-inputs'),
        ('vmacc.vx v8, a0, v16', 8, 1, 'other-sew'),
        ('vmacc.vx v8, a0, v16', 32, 1, 'other-sew'),
        ('vmacc.vx v8, a0, v16', 64, 1, 'other-sew'),
        ('vmacc.vx v8, a0, v16', 16, 0.5, 'other-lmul'),
        ('vmacc.vx v8, a0, v16', 16, 2, 'other-lmul'),
        ('vwmacc.vv v8, v16, v24', 8, 1, 'other-sew'),
        ('vwmacc.vv v8, v16, v24', 32, 1, 'other-sew'),
        ('vwmacc.vv v8, v16, v24', 16, 0.5, 'other-lmul'),
        ('vwmacc.vv v8, v16, v24', 16, 2, 'other-lmul'),
    )
    for command, sew, lmul, purpose in extras:
        result.setdefault((command, sew, lmul), {'source_pcs': [], 'purpose': purpose})
    if direction == 'reverse':
        result[('vwmacc.vv v8, v16, v24, v0.t', 16, 1)] = {'source_pcs': [], 'purpose': 'masked-side-path'}
    return [(command, sew, lmul, metadata) for (command, sew, lmul), metadata in result.items()]


def c_source(metadata, direction):
    text = ORIGINAL.with_suffix('.c').read_text()
    text = replace_once(text, '#define RECORD_SIZE (STATE_SIZE + MEMORY_SIZE + 512 + 16)',
                        '#define RECORD_SIZE (STATE_SIZE + MEMORY_SIZE + 512 + 24)')
    text = replace_once(text, 'uint64_t input_vl, input_vtype, input_vcsr, input_fcsr, actual_fcsr, actual_vcsr;',
                        'uint64_t input_vl, input_vtype, input_vcsr, input_fcsr, actual_fcsr, actual_vcsr;\n'
                        'uint64_t input_vstart, observed_input_vstart, actual_vstart, input_scalar;')
    text = replace_once(text, 'frm=%u\\n", message, index, vl, vcsr, frm);',
                        'frm=%u vstart=%llu\\n", message, index, vl, vcsr, frm, (unsigned long long)input_vstart);')
    before = '''        unsigned block = TARGET_VLENB * 8 * 8 / test->sew;
        const unsigned requested[] = {0, 1, block / 2 - 1, block / 2, block / 2 + 1,
            block - 1, block, block + 1,
            2 * block - 1, 2 * block, 2 * block + 1, test->vlmax - 1, test->vlmax};'''
    if not (text.count(before) == 1):
        raise ValueError('statecheck invariant failed: text.count(before) == 1')
    text = replace_once(text, before, '''        const unsigned requested[] = {0, 1, 7, 8, 9, 15, 16, 17,
            31, 32, 33, 63, 64, 65, test->vlmax - 1, test->vlmax};
        const unsigned starts[] = {0, 1, 15, 16, 17, 63, 64, 65};''')
    text = replace_once(text, '                    for (unsigned ci = 0; ci < 3; ++ci) {',
                        '                    for (unsigned ci = 0; ci < 3; ++ci)\n'
                        '                        for (unsigned si = 0; si < (test->restart ? 8u : 1u); ++si) {')
    text = replace_once(text, '                        input_vl = vl;',
                        '                        input_vstart = starts[si]; observed_input_vstart = UINT64_MAX;\n'
                        '                        input_scalar = seed == 1 ? UINT64_C(0xfffffffffffffffd) : UINT64_C(7);\n'
                        '                        input_vl = vl;')
    text = replace_once(text, '                        put(0x1000, 0);', '                        put(0x1000, input_vstart);')
    text = replace_once(text, '                        test->run();', '''                        test->run();
#ifdef NATIVE
                        if (observed_input_vstart != input_vstart) die("native vstart input was not accepted", index, vl, vcsr, frm);
#endif
                        if (actual_vstart != 0) die("hardware vstart was not cleared", index, vl, vcsr, frm);''')
    text = replace_once(text, 'memcpy(record + RECORD_SIZE - 16, &actual_fcsr, 8); memcpy(record + RECORD_SIZE - 8, &actual_vcsr, 8);',
                        'memcpy(record + RECORD_SIZE - 24, &actual_fcsr, 8); memcpy(record + RECORD_SIZE - 16, &actual_vcsr, 8);\n'
                        '                        memcpy(record + RECORD_SIZE - 8, &actual_vstart, 8);')
    if direction == 'forward':
        registers = []
        for entry in metadata:
            vector_regs = re.findall(r'\bv(\d+)\b', entry['command'])
            registers.append((int(vector_regs[0]), int(vector_regs[-1])))
        rows = ',\n'.join(f'    {{{vd}, {vs2}}}' for vd, vs2 in registers)
        helper = '''#ifdef NATIVE
static const unsigned vmacc_registers[][2] = {
''' + rows + '''
};
static void scalar_vmacc_restart(uint8_t *result, const uint8_t *initial,
                                 unsigned vd, unsigned vs2, unsigned vl,
                                 unsigned start, uint64_t scalar) {
    memcpy(result, initial, STATE_SIZE);
    for (unsigned i = start; i < vl; ++i) {
        uint16_t accumulator, source;
        memcpy(&accumulator, initial + vd * SOURCE_VLENB + i * 2, 2);
        memcpy(&source, initial + vs2 * SOURCE_VLENB + i * 2, 2);
        uint16_t value = (uint16_t)((uint32_t)accumulator + (uint32_t)source * (uint16_t)scalar);
        memcpy(result + vd * SOURCE_VLENB + i * 2, &value, 2);
    }
    uint64_t zero = 0;
    memcpy(result + 0x1000, &zero, 8);
}
#endif
'''
        text = replace_once(text, 'int main(int argc, char **argv) {', helper + '\nint main(int argc, char **argv) {')
        text = replace_once(text, '                        test->run();\n#ifdef NATIVE\n'
                            '                        if (observed_input_vstart != input_vstart) die("native vstart input was not accepted", index, vl, vcsr, frm);\n#endif',
                            '''                        unsigned desired_start = (unsigned)input_vstart;
#ifdef NATIVE
                        uint8_t initial_state[STATE_SIZE], zero_state[STATE_SIZE], restart_state[STATE_SIZE];
                        if (test->restart) memcpy(initial_state, simulated_cpu_state, STATE_SIZE);
                        input_vstart = 0;
#endif
                        test->run();
#ifdef NATIVE
                        if (observed_input_vstart != 0) die("native zero vstart input was not accepted", index, vl, vcsr, frm);
                        input_vstart = desired_start;
                        if (test->restart) {
                            unsigned vd = vmacc_registers[index][0], vs2 = vmacc_registers[index][1];
                            scalar_vmacc_restart(zero_state, initial_state, vd, vs2, vl, 0, input_scalar);
                            if (memcmp(zero_state, simulated_cpu_state, STATE_SIZE))
                                die("scalar zero-start vmacc differs from native zero", index, vl, vcsr, frm);
                            scalar_vmacc_restart(restart_state, initial_state, vd, vs2, vl, desired_start, input_scalar);
                            memcpy(simulated_cpu_state, restart_state, STATE_SIZE);
                        }
#endif''')
    return text


def generate(direction, output, translator_root):
    sys.path[:0] = [str(translator_root), str(translator_root / 'src')]
    from riscv.frontend.parser import AsmParser
    from rvv_sbt_rvv import translate as forward
    from rvv_sbt_rvv1024 import translate as reverse
    translate = forward if direction == 'forward' else reverse
    source, target = (128, 32) if direction == 'forward' else (32, 128)
    output.mkdir(parents=True, exist_ok=True)
    declarations, entries, native, candidate, metadata = [], [], [], [], []
    total_records = 0
    cases = selected_cases(direction)
    for index, (command, sew, lmul, details) in enumerate(cases):
        assembly = translate(AsmParser().parse_string(command), raw=True, tls_state=False,
                             init_vtype=f'sew={sew},lmul={lmul:g},tu,mu')
        if 'fallback' in assembly.lower():
            raise ValueError(f'Incomplete state case: {command}, e{sew}, m{lmul}')
        assembly = re.sub(r'\.L_[A-Za-z0-9_]+', lambda m: f'.L_case_{index}_{m[0][3:]}', assembly)
        native.append(wrapper(f'native_{index}', command, source, True, command))
        candidate.append(wrapper(f'candidate_{index}', assembly, source, False, command))
        declarations += [f'extern void native_{index}(void);', f'extern void candidate_{index}(void);']
        token = {0.125: 5, 0.25: 6, 0.5: 7, 1: 0, 2: 1, 4: 2, 8: 3}[lmul]
        vtype = ({8: 0, 16: 1, 32: 2, 64: 3}[sew] << 3) | token
        vlmax = int(source * 8 * lmul / sew)
        restart = direction == 'forward' and command.startswith('vmacc.vx ') and sew == 16 and lmul == 1
        lengths = list(dict.fromkeys(x for x in (0, 1, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, vlmax-1, vlmax) if x <= vlmax))
        starts = [0, 1, 15, 16, 17, 63, 64, 65] if restart else [0]
        records = len(lengths) * len(starts) * 18
        total_records += records
        entries.append(f'{{FN({index}), {sew}, {vlmax}, {vtype}, 0u, 0u, {int(restart)}}},')
        metadata.append({'index': index, 'command': command, 'sew': sew, 'lmul': lmul,
                         'vlmax': vlmax, 'vl': lengths, 'vstart': starts, 'records': records,
                         'tail_policy': 'canonical tu,mu for defined full-state pairing', **details})
    header = '\n'.join([f'#define SOURCE_VLENB {source}', f'#define TARGET_VLENB {target}', *declarations,
        '#ifdef NATIVE', '#define FN(n) native_##n', '#else', '#define FN(n) candidate_##n', '#endif',
        'struct Case { void (*run)(void); unsigned sew, vlmax, vtype; uint32_t gpr, fpr; unsigned restart; };',
        'static const struct Case cases[] = {', *entries, '};', ''])
    (output / 'cases.h').write_text(header)
    (output / 'native.S').write_text('\n'.join(native))
    (output / 'candidate.S').write_text('\n'.join(candidate))
    (output / 'main.c').write_text(c_source(metadata, direction))
    (output / 'cases.json').write_text(json.dumps(metadata, indent=2) + '\n')
    rejected = []
    for command in ('vmacc.vx v8, a0, v16, v0.t', 'vwmacc.vv v8, v16, v24, v0.t'):
        if direction == 'reverse' and command.startswith('vwmacc.'):
            continue
        result = translate(AsmParser().parse_string(command), raw=True, tls_state=False,
                           init_vtype='sew=16,lmul=1,tu,mu')
        if 'fallback' not in result.lower() or 'ebreak' not in result:
            raise ValueError(f'Unrequested masked support expansion: {command}')
        rejected.append(command)
    manifest = {'direction': direction, 'source_vlenb': source, 'target_vlenb': target,
        'static_cases': len(cases), 'paired_records': total_records, 'record_bytes': 8792,
        'reference_bytes': total_records * 8792,
        'original_wrapper': str(ORIGINAL),
        'wrapper_changes': ['a0 is deterministic arithmetic data, no unconditional memory address',
                            'saved caller ra restored after deterministic guest-ra operand',
                            'actual scalar operand loaded as -3 or 7 by data seed, with scratch register reseeded',
                            'native vstart set and read back before GPR snapshot; target hardware starts at zero',
                            'hardware vstart captured immediately after instruction, before whole-register stores'],
        'negative_mask_scope_checks': rejected,
        'overlap_layout_controls': {
            'case_indices': [entry['index'] for entry in metadata
                             if entry['purpose'] == 'existing-overlap-layout-control'],
            'standard_status': 'Reserved: vwmacc.vv reads old widened vd at EEW32 and overlapping narrow v9 at EEW16; a vector register cannot be a source at multiple EEWs in one instruction',
            'validation_scope': 'Existing K3 overlap-layout implementation controls only; preserved encodings and observed K3 behavior do not establish portable legal-source coverage',
            'references': ['https://github.com/riscv/riscv-isa-manual/blob/main/src/unpriv/vector-common.adoc'],
        },
        'source_flags_boundary': 'Actual kernel uses ta/mu and ta/ma; full-state oracle uses canonical tu/mu to avoid comparing allowed agnostic tails',
        'excluded_scalar': 'sp/gp/tp are not actual MAC scalar operands; no blind comparison of ELF/stack addresses',
        'sha256': {name: hashlib.sha256((output / name).read_bytes()).hexdigest()
                   for name in ('native.S','candidate.S','main.c','cases.h','cases.json')}}
    if direction == 'forward':
        manifest['nonzero_vstart_oracle'] = {
            'confirmed_native_vstart': [0],
            'observed_source_failure': 'A100 source-native baseline case0 e16/m1: VL0/start0 first record, VL0/start1 SIGILL exit132; partial reference8192B; other nonzero combinations not yet classified',
            'reference': 'Native hardware always executes start0; independent scalar e16 modular MAC first validates whole zero-start state then constructs desired suffix state',
            'target': 'Real desired vstart remains in simulated source state and is checked against independent scalar restart output',
            'native_assembly_and_case_header_unchanged': True,
        }
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({k: manifest[k] for k in ('direction','static_cases','paired_records','reference_bytes')}, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Main Q3 MAC full-state source-native gate')
    parser.add_argument('--direction', choices=('forward','reverse'), required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--translator-root', type=Path, default=REPO_ROOT)
    args = parser.parse_args()
    generate(args.direction, args.out, args.translator_root)
