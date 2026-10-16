from __future__ import annotations

from fractions import Fraction
import unittest

from chimera.preprocess.offline.analysis.arch.riscv import RiscvServices
from chimera.preprocess.offline.analysis.arch.riscv.rvv import RvvServices
from chimera.preprocess.offline.analysis.arch.riscv.rvv.config import (
    AVLKind,
    VectorConfig,
)
from chimera.preprocess.offline.analysis.core.data_model import Instruction


class RiscvStackSemanticsTests(unittest.TestCase):
    def test_scalar_register_reads_include_arithmetic_and_memory_bases(self) -> None:
        semantics = RvvServices().stack_semantics
        instruction = Instruction(
            addr=0x1000,
            size=4,
            op="sub",
            args=["sp", "sp", "a3"],
            text="sub sp,sp,a3",
        )

        self.assertEqual(semantics.read_scalar_registers(instruction), {"sp", "a3"})

    def test_all_riscv_csr_read_forms_preserve_vlenb_symbol(self) -> None:
        semantics = RvvServices().stack_semantics
        for op in ("csrr", "csrrs", "csrrc", "csrrw", "csrrsi", "csrrci", "csrrwi"):
            instruction = Instruction(
                addr=0x1000,
                size=4,
                op=op,
                args=["a0", "vlenb", "zero"],
                text=f"{op} a0,vlenb,zero",
            )
            state = semantics.symbolic.initial_state()
            self.assertEqual(str(semantics.symbolic.transfer_instruction(instruction, state)["a0"]), "VLENB")

    def test_scalar_load_with_address_operand_is_not_vector_memory(self) -> None:
        semantics = RvvServices().stack_semantics
        instruction = Instruction(
            addr=0x3BD38,
            size=2,
            op="ld",
            args=["s3", "24(sp)"],
            text="ld s3,24(sp)",
        )

        self.assertIsNone(semantics.vector_memory_operand(instruction))

    def test_vector_load_keeps_its_address_operand(self) -> None:
        semantics = RvvServices().stack_semantics
        instruction = Instruction(
            addr=0x3BCB6,
            size=4,
            op="vle8ff.v",
            args=["v1", "(a2)"],
            text="vle8ff.v v1,(a2)",
        )

        self.assertEqual(semantics.vector_memory_operand(instruction), "(a2)")
        self.assertEqual(semantics.stack_access_kind(instruction), "load")


class VLenSensitivityTests(unittest.TestCase):
    """Constant-AVL sensitivity: AVL * SEW > 128 * LMUL (spec-min VLEN)."""

    @staticmethod
    def _sensitive(avl: int, sew: int, lmul: Fraction) -> bool:
        config = VectorConfig(
            sew=sew,
            lmul=lmul,
            avl_kind=AVLKind.CONSTANT,
            avl_value=avl,
        )
        return RvvServices().stack_semantics.is_vlen_sensitive_config(
            config, min_vlen_bits=256
        )

    def test_grouped_copy_fitting_min_vlmax_is_not_sensitive(self) -> None:
        # vsetivli zero,8,e64,m4: VLMAX(128) = 8 >= AVL -> fixed 64 bytes.
        self.assertFalse(self._sensitive(8, 64, Fraction(4)))

    def test_ungrouped_oversized_avl_is_sensitive(self) -> None:
        # vsetivli zero,8,e64,m1: VLMAX(128) = 2 < 8 -> vl truncated.
        self.assertTrue(self._sensitive(8, 64, Fraction(1)))

    def test_small_sew_oversized_avl_is_sensitive(self) -> None:
        # vsetivli zero,32,e8,m1: VLMAX(128) = 16 < 32 -> byte count varies.
        self.assertTrue(self._sensitive(32, 8, Fraction(1)))

    def test_avl_equal_to_min_vlmax_is_not_sensitive(self) -> None:
        # Boundary: AVL == VLMAX(128) -> vl == AVL on every legal VLEN.
        self.assertFalse(self._sensitive(16, 8, Fraction(1)))

    def test_fractional_lmul_participates(self) -> None:
        # e32,mf8: VLMAX(128) = 128/8/32 = 0.5 -> any AVL >= 1 is sensitive.
        self.assertTrue(self._sensitive(1, 32, Fraction(1, 8)))
        # e64,mf8: VLMAX(128) = 128/8/64 = 0.25 -> sensitive as well.
        self.assertTrue(self._sensitive(1, 64, Fraction(1, 8)))

    def test_x0_avl_is_always_sensitive(self) -> None:
        config = VectorConfig(sew=64, lmul=Fraction(1), avl_kind=AVLKind.X0)
        self.assertTrue(
            RvvServices().stack_semantics.is_vlen_sensitive_config(
                config, min_vlen_bits=256
            )
        )

    def test_unknown_lmul_is_not_sensitive(self) -> None:
        config = VectorConfig(
            sew=64,
            lmul=None,
            avl_kind=AVLKind.CONSTANT,
            avl_value=8,
        )
        self.assertFalse(
            RvvServices().stack_semantics.is_vlen_sensitive_config(
                config, min_vlen_bits=256
            )
        )

    def test_unknown_avl_is_not_sensitive(self) -> None:
        config = VectorConfig(sew=64, lmul=Fraction(1), avl_kind=AVLKind.UNKNOWN)
        self.assertFalse(
            RvvServices().stack_semantics.is_vlen_sensitive_config(
                config, min_vlen_bits=256
            )
        )


if __name__ == "__main__":
    unittest.main()
