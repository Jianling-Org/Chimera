"""两条 RVV 翻译路径的新状态符号和查表 profile 契约测试。

这些测试只检查翻译器发射的文本 ABI：

* RVV1024→RVV256 必须访问独立状态符号并传 a0=1；
* RVV256→RVV1024 必须访问另一状态符号并传 a0=2。

目录外的 TLS 定义、查表 C 实现和真实迁移行为由运行时集成测试负责。
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from riscv.frontend.parser import AsmParser
from riscv.extensions.rvv.translation.emitter import ProgramEmitter
from riscv.extensions.rvv.runtime.contract import RVV1024_TO_RVV256, RVV256_TO_RVV1024
from riscv.frontend.model import RVProgram
from rvv_sbt_rvv import translate as translate_rvv256
from rvv_sbt_rvv import translate_program as translate_program_rvv256
from rvv_sbt_rvv1024 import translate as translate_rvv1024
from rvv_sbt_rvv1024 import translate_program as translate_program_rvv1024


def _instructions(source: str):
    """使用正式汇编解析器构造两条后端共用的输入指令。"""

    return AsmParser().parse_string(source)


def _program_with_indirect_exit() -> RVProgram:
    """构造包含向量配置和间接退出的最小程序级输入。"""

    functions = AsmParser().parse_string_functions(
        """
0000000000001000 <foo>:
    1000: 0d0577d7             vsetvli a5, a0, e32, m1, ta, ma
    1004: 00008067             jr      ra
"""
    )
    return RVProgram(functions=list(functions))


def test_new_contract_symbols_use_riscv64_qualified_segments():
    """双向状态符号的每个架构段都必须明确写成 riscv64。"""
    for contract in (RVV1024_TO_RVV256, RVV256_TO_RVV1024):
        assert "riscv_rvv_" not in contract.state_symbol
        assert "riscv_rvv_" not in contract.non_tls_state_symbol
        assert "riscv64_rvv_" in contract.state_symbol


def test_rvv1024_to_rvv256_uses_contract_state_and_profile():
    """1024→256 单函数输出必须使用新 TLS 状态符号。"""

    output = translate_rvv256(
        _instructions("vadd.vv v8, v16, v24"),
        init_vtype="sew=32,lmul=1",
        raw=True,
    )

    assert (
        f"la.tls.ie t6, {RVV1024_TO_RVV256.state_symbol}"
        in output
    )
    assert "simulated_cpu_state_ptr" not in output


def test_rvv256_to_rvv1024_uses_contract_state_and_profile():
    """256→1024 单函数输出必须使用另一套紧凑状态符号。"""

    output = translate_rvv1024(
        _instructions("vadd.vv v8, v16, v24"),
        init_vtype="sew=32,lmul=1",
        raw=True,
    )

    assert (
        f"la.tls.ie t6, {RVV256_TO_RVV1024.state_symbol}"
        in output
    )
    assert "simulated_cpu_state_ptr" not in output
    assert RVV1024_TO_RVV256.state_symbol not in output


def test_program_lookup_profile_is_one_for_rvv1024_to_rvv256():
    """1024→256 程序级间接跳转必须把 profile 1 放入查表函数 a0。"""

    output = translate_program_rvv256(_program_with_indirect_exit())

    assert "call    query_original_translated_map@plt" in output
    assert "li      a0, 1" in output
    assert "li      a0, 2" not in output


def test_program_lookup_profile_is_two_for_rvv256_to_rvv1024():
    """256→1024 程序级间接跳转必须把 profile 2 放入查表函数 a0。"""

    output = translate_program_rvv1024(_program_with_indirect_exit())

    assert "call    query_original_translated_map@plt" in output
    assert "li      a0, 2" in output
    assert "li      a0, 1" not in output


def test_legacy_non_tls_fixture_name_remains_compatible():
    """旧 emitter 的非 TLS fixture 仍使用本地对象名，专用路径才使用新符号。"""

    legacy = ProgramEmitter()
    assert legacy.state_access.emit_base_load(tls_state=False) == [
        "    la      t6, simulated_cpu_state"
    ]

    from rvv_sbt_rvv import _make_emitter as make_rvv256_emitter
    from rvv_sbt_rvv1024 import _make_emitter as make_rvv1024_emitter

    assert make_rvv256_emitter().state_access.emit_base_load(tls_state=False) == [
        f"    la      t6, {RVV1024_TO_RVV256.state_symbol}"
    ]
    assert make_rvv1024_emitter().state_access.emit_base_load(tls_state=False) == [
        f"    la      t6, {RVV256_TO_RVV1024.state_symbol}"
    ]
