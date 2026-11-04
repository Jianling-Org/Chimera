"""Actual LLVM inlining: RVV definitions retain Gate; scalar wrappers still fold."""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile


def function(text, name):
    match = re.search(r'define [^{]*@'+re.escape(name)+r'\([^\n]*\)[^{]*\{', text)
    assert match, name
    return text[match.start():text.index('\n}', match.end())+2]


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--opt',required=True);p.add_argument('--plugin',required=True)
    p.add_argument('--output',type=Path)
    a=p.parse_args();fixture=Path(__file__).with_name('call-boundaries.ll')
    with tempfile.TemporaryDirectory(prefix='chimera-rvv-boundaries-') as temporary:
        out=a.output or Path(temporary);out.mkdir(parents=True,exist_ok=True)
        source=out/'input.ll'
        source.write_text(fixture.read_text()+'\ndefine <vscale x 4 x i32> @unreachable_rvv(<vscale x 4 x i32> %v) alwaysinline {\n  ret <vscale x 4 x i32> %v\n}\n')
        for count in (1,2):
            pipeline=','.join(['chimera-gate-rvv-boundaries']*count+[
                'always-inline','instcombine','always-inline','verify'])
            r=subprocess.run([a.opt,'-load-pass-plugin='+a.plugin,'-passes='+pipeline,
                              '-S',str(source),'-o',str(out/f'pass{count}.ll')],
                             capture_output=True,text=True)
            assert r.returncode==0,r.stderr
        text=(out/'pass1.ll').read_text()
        assert text==(out/'pass2.ll').read_text(),'Boundary pass is not idempotent'
        for name in ['gated_caller','gated_wrapper','gated_callback_wrapper','open_caller']:
            body=function(text,name)
            assert '@vector_leaf(' in body,name
            assert '<vscale x 4 x i32>' not in body,name
            assert '@wrapper(' not in body,name
            assert '@scalar_helper(' not in body,name
        assert 'add i32' in function(text,'gated_caller')
        assert 'add i32' in function(text,'gated_callback_wrapper')
        assert 'call void %' not in function(text,'gated_callback_wrapper')
        width=function(text,'gated_width_query')
        assert '@llvm.vscale.i64(' in width and '@width_query(' not in width
        for name in ['vector_leaf','preemptable_vector','self_vector',
                     'self_bits_vector','vector_nodup']:
            body=function(text,name)
            group=re.search(r' #(\d+)\s*\{',body)
            assert group,name
            attrs=re.search(r'attributes #'+group[1]+r' = \{([^\n]*)\}',text)[1]
            assert 'noinline' in attrs and 'alwaysinline' not in attrs,(name,attrs)
            assert '"chimera-no-vectorize"' in attrs,(name,attrs)
        for name in ['scalar_helper','scalar_callback','wrapper','width_query']:
            # Successfully inlined internal definitions may be deleted.
            if not re.search(r'define [^{]*@'+name+r'\(',text):
                continue
            body=function(text,name)
            group=re.search(r' #(\d+)\s*\{',body)
            if group:
                attrs=re.search(r'attributes #'+group[1]+r' = \{([^\n]*)\}',text)[1]
                assert 'noinline' not in attrs and 'chimera-rvv-call-boundary' not in attrs,(name,attrs)
        for callee,caller in [('preemptable_vector','gated_preemptable'),
                              ('self_vector','gated_self_pointer'),
                              ('self_bits_vector','gated_self_bits'),
                              ('vector_nodup','gated_nodup')]:
            assert '@'+callee+'(' in function(text,caller)
        assert 'ret ptr @self_vector' in function(text,'self_vector')
        assert '@__chimera.gated.' not in text
        unused=function(text,'unreachable_rvv')
        group=re.search(r' #(\d+)\s*\{',unused)
        attrs=re.search(r'attributes #'+group[1]+r' = \{([^\n]*)\}',text)[1]
        assert 'alwaysinline' in attrs and 'chimera-no-vectorize' not in attrs
        no_roots=out/'no-roots.ll'
        no_roots.write_text(source.read_text().replace(' "chimera-no-vectorize"',''))
        for name,pipeline in [('original','verify'),('boundary','chimera-gate-rvv-boundaries,verify')]:
            r=subprocess.run([a.opt,'-load-pass-plugin='+a.plugin,'-passes='+pipeline,'-S',
                              str(no_roots),'-o',str(out/(name+'-no-roots.ll'))],
                             capture_output=True,text=True)
            assert r.returncode==0,r.stderr
        assert (out/'original-no-roots.ll').read_bytes()==(out/'boundary-no-roots.ll').read_bytes()
        print('PASS: explicit RVV stays in Gate+noinline definitions; scalar/width/callback '
              'specialization retained; identities, linkage and repeated passes preserved')


if __name__=='__main__':main()
