"""Execute forward CSR virtualization and reject illegal CSR writes."""

from pathlib import Path
import subprocess

import pytest

from riscv.extensions.rvv.analysis.config import StateTracker
from riscv.extensions.rvv.backends.rvv256.backend import RVV256Dispatcher
from riscv.extensions.rvv.runtime.contract import RVV1024_TO_RVV256
from riscv.extensions.rvv.runtime.layout import SimulatedStateLayout
from riscv.extensions.rvv.translation.contracts import VStartPolicy
from riscv.frontend.parser import AsmParser
from rvv_sbt_rvv import translate
from test_rvv256_vstart import _START, _LINK, riscv_tools


_FORMS = ["csrr a2,{csr}", "csrw {csr},a2", "csrs {csr},a2", "csrc {csr},a2",
          "csrwi {csr},2", "csrsi {csr},2", "csrci {csr},2", "csrrw a2,{csr},a2",
          "csrrs a2,{csr},a2", "csrrc a2,{csr},a2", "csrrwi a2,{csr},2",
          "csrrsi a2,{csr},2", "csrrci a2,{csr},2"]


def _run(tmp_path: Path, riscv_tools, command: str, rd="a2", *, backend="forward"):
    compiler, qemu = riscv_tools
    symbol = ("simulated_cpu_state" if backend == "scalar" else
              RVV1024_TO_RVV256.non_tls_state_symbol)
    code = f'''
#include <stdint.h>
uint8_t state[0x1040] __attribute__((aligned(128)));
uint64_t observed[8];
__asm__(".globl {symbol}\\n.set {symbol}, state\\n");
extern void probe(void);
int main(void) {{
    *(uint64_t *)(state + 0x1000) = 3;
    *(uint64_t *)(state + 0x1008) = 0;
    *(uint64_t *)(state + 0x1010) = 0;
    *(uint64_t *)(state + 0x1018) = 5;
    *(uint64_t *)(state + 0x1020) = 4;
    *(uint64_t *)(state + 0x1028) = 16;
    *(uint64_t *)(state + 0x1030) = 128;
    probe();
    for(unsigned i=0;i<sizeof(observed);i++) {{
        unsigned char byte=((unsigned char*)observed)[i];
        *(volatile char *)0x10000000="0123456789abcdef"[byte>>4];
        *(volatile char *)0x10000000="0123456789abcdef"[byte&15];
    }}
    *(volatile char *)0x10000000='\\n';
    return 0;
}}
'''
    capture = f"""
    mv t3,{rd}
    mv sp,s11
    la s1,observed
    sd t3,0(s1)
"""
    for index, csr in enumerate(("vstart", "vxrm", "vxsat", "vcsr", "vl", "vtype", "vlenb"), 1):
        capture += f"    csrr t3,{csr}\n    sd t3,{index * 8}(s1)\n"
    program = command + "\n" + capture
    if backend == "scalar":
        from test_review_arithmetic_execution import _translated
        translated = _translated(program, 32, 1, "scalar")
    else:
        translated = translate(AsmParser().parse_string(program), raw=True, tls_state=False)
    assert "fallback" not in translated and "ebreak" not in translated
    (tmp_path / "main.c").write_text(code)
    (tmp_path / "link.ld").write_text(_LINK)
    (tmp_path / "start.S").write_text(_START.replace("\ntrap:", "\n.balign 4\ntrap:"))
    outputs = []
    for name, body, vlen in (("native", program, 1024), ("translated", translated, 256)):
        initialize = ""
        if name == "native":
            initialize = "vsetivli zero,4,e32,m1,tu,mu\ncsrwi vcsr,5\ncsrwi vstart,3\n"
        assembly = f""".text
.globl probe
probe:
    addi sp,sp,-16
    sd s1,0(sp)
    sd s11,8(sp)
    mv s11,sp
{initialize}
    li a2,2
    li t6,2
{body}
    mv sp,s11
    ld s1,0(sp)
    ld s11,8(sp)
    addi sp,sp,16
    ret
"""
        (tmp_path / f"{name}.S").write_text(assembly)
        build = subprocess.run([
            compiler, "-march=rv64gcv", "-mabi=lp64d", "-mcmodel=medany", "-msmall-data-limit=0",
            "-fno-tree-vectorize", "-fno-builtin", "-ffreestanding", "-nostdlib", "-O2",
            "-T", "link.ld", "start.S", "main.c", f"{name}.S", "-o", f"{name}.elf",
        ], cwd=tmp_path, capture_output=True, text=True, timeout=30)
        assert build.returncode == 0, build.stderr
        result = subprocess.run([
            qemu, "-M", "virt", "-cpu", f"rv64,v=true,vlen={vlen},elen=64", "-m", "128M",
            "-nographic", "-bios", "none", "-kernel", str(tmp_path / f"{name}.elf"),
        ], capture_output=True, text=True, timeout=20)
        assert result.returncode == 0 and len(result.stdout.strip()) == 128, result.stdout
        (tmp_path / f"{name}.stdout").write_text(result.stdout)
        outputs.append(result.stdout)
    assert outputs[0] == outputs[1]


@pytest.mark.parametrize("form", _FORMS)
@pytest.mark.parametrize("csr", ["vstart", "vxrm", "vxsat", "vcsr"])
def test_vector_csr_forms_match_native(tmp_path, riscv_tools, form, csr):
    _run(tmp_path, riscv_tools, form.format(csr=csr))


@pytest.mark.parametrize("csr", ["vl", "vtype", "vlenb", "0xc20", "0x0c21", "3106"])
@pytest.mark.parametrize("form", ["csrrs a2,{csr},zero", "csrrc a2,{csr},x0",
                                  "csrrsi a2,{csr},0", "csrrci a2,{csr},0"])
def test_read_only_csr_zero_mask_read(tmp_path, riscv_tools, csr, form):
    _run(tmp_path, riscv_tools, form.format(csr=csr))


@pytest.mark.parametrize("rd", ["t6", "x31", "sp", "x2"])
@pytest.mark.parametrize("opcode", ["csrrw", "csrrs", "csrrc"])
def test_csr_state_base_stack_and_input_output_alias(tmp_path, riscv_tools, rd, opcode):
    source = rd
    _run(tmp_path, riscv_tools, f"{opcode} {rd},vcsr,{source}", rd=rd)


@pytest.mark.parametrize("command", [
    "csrwi vstart,1\ncsrwi vstart,0", "csrwi 0x00a,2\ncsrr a2,10",
    "csrwi vcsr,31\ncsrr a2,0x00f", "li a2,-1\ncsrw vstart,a2\ncsrr a2,vstart",
    "vsetivli a2,4,e32,m1,tu,mu",
    "vsetvli a2,zero,e32,m1,tu,mu",
    "li a1,16\nvsetvl a2,zero,a1",
    "vsetivli t6,4,e32,m1,tu,mu\nmv a2,t6",
    "li a1,-1\nvsetvl a2,zero,a1",
])
def test_csr_sequences_and_numeric_aliases(tmp_path, riscv_tools, command):
    _run(tmp_path, riscv_tools, command)


@pytest.mark.parametrize("command", [
    "csrw vl,zero", "csrwi vlenb,0", "csrrw a0,vtype,zero", "csrrwi zero,vl,0",
    "csrrs a0,vl,a2", "csrrsi a0,vtype,1", "csrrc a0,vlenb,a2",
    "csrwi vxrm,-1", "csrwi vxrm,32", "csrrsi a0,vxsat,32", "csrrci a0,vcsr,-1",
])
def test_invalid_csr_updates_are_rejected(command):
    output = translate(AsmParser().parse_string(command), raw=True)
    assert "fallback" in output and "ebreak" in output


def test_csr_metadata_and_nonvector_passthrough():
    dispatcher = RVV256Dispatcher()
    for form in _FORMS:
        insn = AsmParser().parse_string(form.format(csr="vcsr"))[0]
        assert dispatcher.handles_scalar_instruction(insn)
        spec = dispatcher.registry.require(insn.opcode)
        assert spec.vtype_independent
        assert spec.vstart_policy is VStartPolicy.NOT_APPLICABLE
    assert not dispatcher.handles_scalar_instruction(AsmParser().parse_string("csrwi fflags,0")[0])
    assert translate(AsmParser().parse_string("csrwi fflags,0"), raw=True).strip() == "csrwi    fflags, 0"
    clip = dispatcher.registry.require("vnclip.wi")
    assert "vcsr" in clip.state_reads and "vcsr" in clip.state_writes
    for opcode in ("vsetvli", "vsetivli", "vsetvl"):
        assert "vstart" in dispatcher.registry.require(opcode).state_writes


def test_csr_rounding_write_reaches_following_narrowing(tmp_path, riscv_tools):
    from test_review_arithmetic_execution import _compare

    _compare(tmp_path, riscv_tools, "csrwi vxrm,2\nvnclip.wi v8,v16,1", sew=16,
             initialize="for(unsigned i=0;i<128/4;i++) ((uint32_t *)(state+16*128))[i]=1;")
