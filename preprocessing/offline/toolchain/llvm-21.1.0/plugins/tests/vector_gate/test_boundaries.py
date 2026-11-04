"""Exercise actual LLVM transformations and scalar memory results, not source text."""
import argparse
import ctypes
import platform
from pathlib import Path
import re
import subprocess
import tempfile


def body(text, name):
    match = re.search(r"define [^{]*@"+re.escape(name)+r"\([^\n]*\)[^{]*\{", text)
    if not match:
        raise AssertionError('Missing function '+name)
    return text[match.end():text.index('\n}', match.end())]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--opt', required=True)
    parser.add_argument('--llc', required=True)
    parser.add_argument('--cc', default='cc')
    parser.add_argument('--plugin', required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    here = Path(__file__).resolve().parent
    with tempfile.TemporaryDirectory(prefix='chimera-gate-boundaries-') as temporary:
        out = args.output or Path(temporary)
        out.mkdir(exist_ok=True, parents=True)

        def run(*argv):
            result = subprocess.run(list(map(str, argv)), capture_output=True, text=True)
            if result.returncode:
                raise AssertionError(str(argv)+'\n'+result.stdout+'\n'+result.stderr)
            return result.stdout

        call_ir = out/'call-boundaries.ll'
        inline_pipeline = 'always-inline,instcombine,always-inline,'
        run(args.opt, '-load-pass-plugin='+args.plugin,
            '-passes='+inline_pipeline+'chimera-gate-local-memsets,verify', '-S',
            here/'call-boundaries.ll', '-o', call_ir)
        text = call_ir.read_text()
        baseline = out/'original-inlining.ll'
        run(args.opt, '-passes='+inline_pipeline+'verify', '-S',
            here/'call-boundaries.ll', '-o', baseline)
        assert text == baseline.read_text(), 'Memory pass changed unrelated inlining or control flow'
        assert '@vector_leaf(' not in body(text, 'gated_caller')
        assert '<vscale x 4 x i32>' in body(text, 'gated_caller')
        assert '@scalar_helper(' not in body(text, 'gated_caller')
        assert 'add i32' in body(text, 'gated_caller')
        assert '@vector_leaf(' not in body(text, 'open_caller')
        assert '<vscale x 4 x i32>' in body(text, 'open_caller')
        assert '@wrapper(' not in body(text, 'gated_wrapper')
        assert '<vscale x 4 x i32>' in body(text, 'gated_wrapper')
        assert '@width_query(' not in body(text, 'gated_width_query')
        assert '@llvm.vscale.i64(' in body(text, 'gated_width_query')
        assert '@scalar_callback(' not in body(text, 'gated_callback_wrapper')
        assert 'call void %' not in body(text, 'gated_callback_wrapper')
        assert 'add i32' in body(text, 'gated_callback_wrapper')
        for name, caller in [('preemptable_vector', 'gated_preemptable'),
                             ('self_vector', 'gated_self_pointer'),
                             ('self_bits_vector', 'gated_self_bits'),
                             ('vector_nodup', 'gated_nodup')]:
            assert '@__chimera.gated.'+name not in text
            assert '@'+name+'(' in body(text, caller)

        memset_ir = out/'local-memsets.ll'
        run(args.opt, '-load-pass-plugin='+args.plugin,
            '-passes=chimera-gate-local-memsets,chimera-gate-local-memsets,verify', '-S',
            here/'local-memsets.ll', '-o', memset_ir)
        text = memset_ir.read_text()
        for name in ('gated_fill', 'gated_volatile_fill', 'gated_fill32', 'gated_zero_length'):
            assert '@llvm.memset.' not in body(text, name)
            assert '@memset(' not in body(text, name)
        assert 'store volatile i8' in body(text, 'gated_volatile_fill')
        assert 'store ' not in body(text, 'gated_zero_length')
        assert '@llvm.memset.' in body(text, 'open_fill')
        assert '@memset(' in body(text, 'gated_real_call')
        # LLVM GEP sign-extends narrow indices. Inspect the actual generated
        # offset's unsigned widening; small executions cannot cover >= 2 GiB.
        narrow = body(text, 'gated_fill32')
        assert re.search(r'zext i32 %chimera.memset.index to i64', narrow)
        assert re.search(r'getelementptr i8, ptr %dst, i64 %chimera.memset.offset', narrow)

        # Compile and execute the transformed memory functions on this host.
        obj = out/'local-memsets.o'
        library = out/'local-memsets.so'
        # llc's generic RV64 default is soft-float, unlike the native Linux
        # LP64D linker/Python process that executes this shared object.
        native_abi = (['-mattr=+m,+a,+f,+d,+c', '-target-abi=lp64d']
                      if platform.machine() == 'riscv64' else [])
        run(args.llc, '-filetype=obj', '-relocation-model=pic', *native_abi, memset_ir, '-o', obj)
        run(args.cc, '-shared', obj, '-o', library)
        lib = ctypes.CDLL(str(library.resolve()))
        cases = 0
        for name in ('gated_fill', 'gated_volatile_fill', 'gated_fill32'):
            fn = getattr(lib, name)
            count_type = ctypes.c_uint32 if name == 'gated_fill32' else ctypes.c_uint64
            fn.argtypes = [ctypes.c_void_p, ctypes.c_ubyte, count_type]
            fn.restype = None
            fn(None, 0, 0)
            for length in (0, 1, 2, 7, 16, 31, 256, 1025):
                for value in (0, 0x41, 0x80, 0xff):
                    storage = (ctypes.c_ubyte*(length+2))(*([0xcc]*(length+2)))
                    storage[0], storage[-1] = 0xa5, 0x5a
                    fn(ctypes.byref(storage, 1), value, length)
                    assert bytes(storage) == bytes([0xa5])+bytes([value])*length+bytes([0x5a])
                    cases += 1
        lib.gated_zero_length.argtypes = [ctypes.c_void_p]
        lib.gated_zero_length.restype = None
        lib.gated_zero_length(None)
        print('PASS: unchanged explicit-RVV/control/scalar/width inlining, intrinsic-only lowering, '
              f'volatile and zero-length behavior, {cases} guarded memory outputs')


if __name__ == '__main__':
    main()
