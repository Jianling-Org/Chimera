import pytest
from riscv.frontend.parser import AsmParser
from riscv.codegen.control_flow import ControlFlowEmitter


@pytest.mark.parametrize('command,register,offset', [
    ('ret',1,0), ('jr t0',5,0), ('jalr zero, -8(a1)',11,-8),
    ('jalr zero, 8(sp)',2,8), ('jalr zero, 0(zero)',0,0),
])
def test_exact_dispatch_metadata_after_complete_register_restoration(command,register,offset):
    insn=AsmParser().parse_string(command)[0]
    insn.address=0x1000
    emitter=ControlFlowEmitter(lookup_profile=2)
    args=dict(context=None, active_long_jump_veneers={})
    output='\n'.join(emitter.emit_program_scalar(insn,insn.operands,'main_original_base_addr',emit_indirect_sites=True,**args))
    label='.Lchimera_no_link_1000:'
    assert label in output
    before,after=output.split(label)
    assert before.rfind('ld      ra,') > before.rfind('addi    sp, sp,')
    assert after.startswith('\n    # Unsupported no-link indirect target remap\n    ebreak')
    assert '.quad .Lchimera_no_link_1000\n    .quad 320\n    .quad 296\n    .quad 4096' in after
    legacy='\n'.join(emitter.emit_program_scalar(insn,insn.operands,'main_original_base_addr',**args))
    assert label not in legacy
    assert '    # Unsupported no-link indirect target remap\n    ebreak' in legacy


@pytest.mark.parametrize('direction',[1,2])
def test_program_exports_variant_scoped_table_and_text_only_omits_it(direction):
    from rvv_sbt_rvv import translate_program as forward
    from rvv_sbt_rvv1024 import translate_program as reverse
    program=AsmParser().parse_string_program('0000000000001000 <foo>:\n    1000: 8082 ret\n')
    translate=forward if direction==1 else reverse
    output=translate(program,lib_name='test_variant')
    assert 'chimera_test_variant_no_link_entries:' in output
    assert 'chimera_test_variant_no_link_count:' in output
    assert 'chimera_test_variant_no_link_abi:' in output
    assert '.quad .Lchimera_no_link_1000' in output
    text=translate(program,lib_name='test_variant',text_only=True)
    assert 'chimera_no_link' not in text


@pytest.mark.parametrize('direction',[1,2])
def test_native_dso_relocates_exact_trap_table(tmp_path,direction):
    import ctypes,os,platform,subprocess
    if platform.machine() not in ('riscv64','riscv'):
        pytest.skip('requires native RV64 assembler and loader')
    from rvv_sbt_rvv import translate_program as forward
    from rvv_sbt_rvv1024 import translate_program as reverse
    program=AsmParser().parse_string_program('0000000000001000 <foo>:\n    1000: 8082 ret\n0000000000001002 <bar>:\n    1002: 8282 jr t0\n')
    name=f'no_link_native_{direction}'
    assembly=tmp_path/'translated.S'
    assembly.write_text((forward if direction==1 else reverse)(program,lib_name=name))
    library=tmp_path/'translated.so'
    subprocess.run(['gcc','-shared','-fPIC','-Wl,-Bsymbolic-functions',str(assembly),'-o',str(library)],check=True,capture_output=True)
    loaded=ctypes.CDLL(str(library),mode=os.RTLD_LAZY|os.RTLD_LOCAL)
    prefix=f'chimera_{name}'
    assert ctypes.c_uint64.in_dll(loaded,prefix+'_no_link_abi').value==1
    count=ctypes.c_uint64.in_dll(loaded,prefix+'_no_link_count').value
    assert count==2
    class Site(ctypes.Structure):
        _fields_=[('pc',ctypes.c_uint64),('frame',ctypes.c_uint64),('slot',ctypes.c_uint64),('original',ctypes.c_uint64)]
    sites=(Site*count).in_dll(loaded,prefix+'_no_link_entries')
    assert [(s.frame,s.slot,s.original) for s in sites]==[(320,296,0x1000),(320,296,0x1002)]
    assert sites[0].pc<sites[1].pc
    for site in sites:
        assert ctypes.c_uint16.from_address(site.pc).value==0x9002


@pytest.mark.parametrize('direction',[1,2])
def test_native_signal_dispatch_preserves_complete_context(tmp_path,direction):
    import platform,subprocess
    from pathlib import Path
    if platform.machine() not in ('riscv64','riscv'):
        pytest.skip('requires native RV64 signal context')
    from rvv_sbt_rvv import translate_program as forward
    from rvv_sbt_rvv1024 import translate_program as reverse
    name=f'no_link_signal_{direction}'
    program=AsmParser().parse_string_program('0000000000001000 <foo>:\n    1000: 8082 ret\n')
    output=(forward if direction==1 else reverse)(program,lib_name=name)
    assembly=tmp_path/'translated.S'
    assembly.write_text(output+'\n.text\n.balign 4\n.globl native_mapped_return\n.protected native_mapped_return\nnative_mapped_return:\n    li a0,77\n    ret\n')
    library=tmp_path/'translated.so'
    subprocess.run(['gcc','-shared','-fPIC','-Wl,-Bsymbolic-functions',str(assembly),'-o',str(library)],check=True,capture_output=True)
    runtime=Path(__file__).resolve().parents[4]/'runtime'
    sources=['runtime/mapping/module_registry.c','runtime/migration/linux_riscv64_rvv_v1/route_id.c','runtime/migration/linux_riscv64_rvv_v1/translation_control.c','runtime/migration/linux_riscv64_rvv_v1/signal_handlers.c','runtime/state/linux_riscv64_rvv_v1/vector_state.c','runtime/state/linux_riscv64_rvv_v1/translator_state.c','interfaces/uapi/linux/chimera_signal.c']
    includes=['interfaces/abi','interfaces/abi/linux_riscv64_rvv_v1','interfaces/uapi/linux','runtime/mapping','runtime/migration/linux_riscv64_rvv_v1','runtime/state/linux_riscv64_rvv_v1']
    executable=tmp_path/'native-signal'
    command=['gcc','-Wall','-Wextra','-Werror','-DCHIMERA_PORTABLE_SIGNAL_TEST=1','-Wl,--export-dynamic',str(Path(__file__).with_name('native_no_link_dispatch.c')),*[str(runtime/p) for p in sources],*[f'-I{runtime/p}' for p in includes],'-ldl','-o',str(executable)]
    compiled=subprocess.run(command,capture_output=True,text=True)
    assert compiled.returncode==0,compiled.stderr
    completed=subprocess.run([str(executable),str(library),name,str(direction)],capture_output=True,text=True,timeout=10)
    assert completed.returncode==0,completed.stdout+completed.stderr
