
tests/fixtures/obj/ccopy_k.o:	file format elf64-littleriscv

Disassembly of section .text:

0000000000000000 <ccopy_k>:
       0: 02a05663     	blez	a0, 0x2c <.L23>
       4: fff60793     	addi	a5, a2, -0x1
       8: e785         	bnez	a5, 0x30 <.L4>
       a: fff70793     	addi	a5, a4, -0x1
       e: e38d         	bnez	a5, 0x30 <.L4>
      10: 0506         	slli	a0, a0, 0x1

0000000000000012 <.L5>:
      12: 0c1577d7     	vsetvli	a5, a0, e8, m2, ta, ma
      16: 0205e407     	vle32.v	v8, (a1)
      1a: 00279713     	slli	a4, a5, 0x2
      1e: 8d1d         	sub	a0, a0, a5
      20: 95ba         	add	a1, a1, a4
      22: 0206e427     	vse32.v	v8, (a3)
      26: 96ba         	add	a3, a3, a4
      28: fea045e3     	bgtz	a0, 0x12 <.L5>

000000000000002c <.L23>:
      2c: 4501         	li	a0, 0x0
      2e: 8082         	ret

0000000000000030 <.L4>:
      30: 4785         	li	a5, 0x1
      32: 04f60763     	beq	a2, a5, 0x80 <.L30>
      36: 060e         	slli	a2, a2, 0x3
      38: 00371813     	slli	a6, a4, 0x3
      3c: 02f70263     	beq	a4, a5, 0x60 <.L10>

0000000000000040 <.L11>:
      40: 0c0577d7     	vsetvli	a5, a0, e8, m1, ta, ma
      44: 2ac5e407     	vlsseg2e32.v	v8, (a1), a2
      48: 02c78733     	mul	a4, a5, a2
      4c: 8d1d         	sub	a0, a0, a5
      4e: 2b06e427     	vssseg2e32.v	v8, (a3), a6
      52: 02f807b3     	mul	a5, a6, a5
      56: 95ba         	add	a1, a1, a4
      58: 96be         	add	a3, a3, a5
      5a: fea043e3     	bgtz	a0, 0x40 <.L11>
      5e: b7f9         	j	0x2c <.L23>

0000000000000060 <.L10>:
      60: 0c0577d7     	vsetvli	a5, a0, e8, m1, ta, ma
      64: 2ac5e407     	vlsseg2e32.v	v8, (a1), a2
      68: 02c78833     	mul	a6, a5, a2
      6c: 00379713     	slli	a4, a5, 0x3
      70: 8d1d         	sub	a0, a0, a5
      72: 2206e427     	vsseg2e32.v	v8, (a3)
      76: 95c2         	add	a1, a1, a6
      78: 96ba         	add	a3, a3, a4
      7a: fea043e3     	bgtz	a0, 0x60 <.L10>
      7e: b77d         	j	0x2c <.L23>

0000000000000080 <.L30>:
      80: 070e         	slli	a4, a4, 0x3

0000000000000082 <.L8>:
      82: 0c0577d7     	vsetvli	a5, a0, e8, m1, ta, ma
      86: 2205e407     	vlseg2e32.v	v8, (a1)
      8a: 02f70633     	mul	a2, a4, a5
      8e: 00379813     	slli	a6, a5, 0x3
      92: 8d1d         	sub	a0, a0, a5
      94: 95c2         	add	a1, a1, a6
      96: 2ae6e427     	vssseg2e32.v	v8, (a3), a4
      9a: 96b2         	add	a3, a3, a2
      9c: fea043e3     	bgtz	a0, 0x82 <.L8>
      a0: 4501         	li	a0, 0x0
      a2: 8082         	ret
