
vadd_rvv.o:	file format elf64-littleriscv

Disassembly of section .text:

0000000000000000 <vadd_rvv>:
       0: c295         	beqz	a3, 0x24 <.L11>

0000000000000002 <.L3>:
       2: 0d06f7d7     	vsetvli	a5, a3, e32, m1, ta, ma
       6: 02056087     	vle32.v	v1, (a0)
       a: 0205e107     	vle32.v	v2, (a1)
       e: 00279713     	slli	a4, a5, 0x2
      12: 8e9d         	sub	a3, a3, a5
      14: 953a         	add	a0, a0, a4
      16: 95ba         	add	a1, a1, a4
      18: 021100d7     	vadd.vv	v1, v1, v2
      1c: 020660a7     	vse32.v	v1, (a2)
      20: 963a         	add	a2, a2, a4
      22: f2e5         	bnez	a3, 0x2 <.L3>

0000000000000024 <.L11>:
      24: 8082         	ret
