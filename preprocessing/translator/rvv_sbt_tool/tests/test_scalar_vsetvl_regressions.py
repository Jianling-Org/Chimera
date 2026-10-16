"""Dynamic scalar vsetvl: AVL selection, aliases, invalid vtype, and vstart."""

import pytest

from test_memory_review_regressions import _execute, _main, _translate, memory_riscv_tools


_FORMS = [
    ("zero", "zero", "a2"), ("x0", "x0", "a2"),
    ("a0", "zero", "a2"), ("a0", "a1", "a2"),
    ("zero", "a1", "a2"), ("a1", "a1", "a2"),
    ("a2", "a1", "a2"), ("t6", "a1", "a2"),
    ("a0", "t6", "a2"), ("a0", "a1", "t6"),
    ("t6", "t6", "a2"), ("t6", "a1", "t6"),
]


def _run_vsetvl_case(tmp_path, tools, form, new_vtype, new_vlmax, *, avl=None, native=True):
    rd, rs1, rs2 = form
    keep = rd in ("zero", "x0") and rs1 in ("zero", "x0")
    invalid = new_vlmax is None or (keep and new_vlmax != 32)
    expected_type = 1 << 63 if invalid else new_vtype
    if invalid:
        expected_vl = "0"
    elif keep:
        expected_vl = "vl"
    elif rs1 in ("zero", "x0"):
        expected_vl = str(new_vlmax)
    else:
        requested = "vl" if avl is None else str(avl)
        expected_vl = f"({requested} < {new_vlmax} ? {requested} : {new_vlmax})"
    expected = f"""
        *(uint64_t *)(expected_state+64+0x1000)=0;
        *(uint64_t *)(expected_state+64+0x1020)={expected_vl};
        *(uint64_t *)(expected_state+64+0x1028)={expected_type}ULL;
    """
    main = _main("simulated_cpu_state", 32, 1, [0, 1, 7], expected)
    main = main.replace("extern void probe(void);", "uint64_t initial_vl;\nextern void probe(void);")
    main = main.replace("    *(uint64_t *)(fixture+64+0x1020)=vl;",
                        "    initial_vl=vl;\n    *(uint64_t *)(fixture+64+0x1000)=2;\n    *(uint64_t *)(fixture+64+0x1020)=vl;")
    command = f"vsetvl {rd},{rs1},{rs2}"
    setup = "    li t6,0x1234\n"
    if rs1 not in ("zero", "x0"):
        if avl is None:
            setup += f"    la t0,initial_vl\n    ld {rs1},0(t0)\n"
        else:
            setup += f"    li {rs1},{avl}\n"
    setup += f"    li {rs2},{new_vtype}\n"
    check = ""
    if rd not in ("zero", "x0"):
        check += f"    la t0,expected_state+64+0x1020\n    ld t1,0(t0)\n    bne {rd},t1,trap\n"
    if rs1 not in ("zero", "x0") and rd != rs1:
        if avl is None:
            check += "    la t0,initial_vl\n    ld t1,0(t0)\n"
        else:
            check += f"    li t1,{avl}\n"
        check += f"    bne {rs1},t1,trap\n"
    if rd != rs2:
        check += f"    li t1,{new_vtype}\n    bne {rs2},t1,trap\n"
    if "t6" not in form:
        check += "    li t1,0x1234\n    bne t6,t1,trap\n"
    candidate = _translate(command, 32, 1, "scalar")
    assert "fallback" not in candidate
    _execute(tmp_path / "translated", tools, setup + candidate + check, main, 256)
    if native:
        body = "    la t0,initial_vl\n    ld t1,0(t0)\n    vsetvli zero,t1,e32,m1,tu,mu\n"
        body += setup + "    csrwi vstart,2\n    " + command + "\n" + check
        for csr, offset in (("vstart", 0x1000), ("vl", 0x1020), ("vtype", 0x1028)):
            body += f"    csrr t1,{csr}\n    la t0,simulated_cpu_state+{offset}\n    sd t1,0(t0)\n"
        _execute(tmp_path / "native", tools, body, main, 1024)


@pytest.mark.parametrize("form", _FORMS)
@pytest.mark.parametrize("new_vtype", [16, 25, 15, 208])
def test_scalar_vsetvl_equal_vlmax_changes_and_aliases(tmp_path, memory_riscv_tools, form, new_vtype):
    _run_vsetvl_case(tmp_path, memory_riscv_tools, form, new_vtype, 32)


@pytest.mark.parametrize("form", _FORMS[2:])
@pytest.mark.parametrize("avl", [None, 64])
def test_scalar_vsetvl_selects_max_or_clamps_avl(tmp_path, memory_riscv_tools, form, avl):
    _run_vsetvl_case(tmp_path, memory_riscv_tools, form, 29, 2, avl=avl)


@pytest.mark.parametrize("new_vtype", [4, 32, 256, 1 << 63])
@pytest.mark.parametrize("form", [("zero", "zero", "a2"), ("a2", "a1", "a2"), ("t6", "a1", "t6")])
def test_scalar_vsetvl_invalid_vtype_sets_vill_and_clears_vstart(tmp_path, memory_riscv_tools, form, new_vtype):
    _run_vsetvl_case(tmp_path, memory_riscv_tools, form, new_vtype, None)


@pytest.mark.parametrize("new_vtype,new_vlmax", [(24, 16), (17, 64)])
def test_scalar_vsetvl_rejects_reserved_keep_vl_vlmax_change(tmp_path, memory_riscv_tools, new_vtype, new_vlmax):
    # Changing VLMAX with rd=rs1=x0 is reserved; verify the translator's vill contract.
    _run_vsetvl_case(tmp_path, memory_riscv_tools, ("zero", "zero", "a2"),
                    new_vtype, new_vlmax, native=False)
