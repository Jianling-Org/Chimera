
tests/fixtures/obj/scopy_k.o:	file format elf64-littleriscv

Disassembly of section .text:

0000000000000000 <scopy_k>:
       0: 02a05563     	blez	a0, 0x2a <.L23>
       4: fff60793     	addi	a5, a2, -0x1
       8: e39d         	bnez	a5, 0x2e <.L3>
       a: fff70793     	addi	a5, a4, -0x1
       e: e385         	bnez	a5, 0x2e <.L3>

0000000000000010 <.L4>:
      10: 0c1577d7     	vsetvli	a5, a0, e8, m2, ta, ma
      14: 0205e407     	vle32.v	v8, (a1)
      18: 00279713     	slli	a4, a5, 0x2
      1c: 8d1d         	sub	a0, a0, a5
      1e: 95ba         	add	a1, a1, a4
      20: 0206e427     	vse32.v	v8, (a3)
      24: 96ba         	add	a3, a3, a4
      26: fea045e3     	bgtz	a0, 0x10 <.L4>

000000000000002a <.L23>:
      2a: 4501         	li	a0, 0x0
      2c: 8082         	ret

000000000000002e <.L3>:
      2e: 4785         	li	a5, 0x1
      30: 04f70763     	beq	a4, a5, 0x7e <.L30>
      34: 070a         	slli	a4, a4, 0x2
      36: 00261813     	slli	a6, a2, 0x2
      3a: 02f60263     	beq	a2, a5, 0x5e <.L9>

000000000000003e <.L10>:
      3e: 0c1577d7     	vsetvli	a5, a0, e8, m2, ta, ma
      42: 0b05e407     	vlse32.v	v8, (a1), a6
      46: 02f80633     	mul	a2, a6, a5
      4a: 8d1d         	sub	a0, a0, a5
      4c: 0ae6e427     	vsse32.v	v8, (a3), a4
      50: 02e787b3     	mul	a5, a5, a4
      54: 95b2         	add	a1, a1, a2
      56: 96be         	add	a3, a3, a5
      58: fea043e3     	bgtz	a0, 0x3e <.L10>
      5c: b7f9         	j	0x2a <.L23>

000000000000005e <.L9>:
      5e: 0c1577d7     	vsetvli	a5, a0, e8, m2, ta, ma
      62: 0205e407     	vle32.v	v8, (a1)
      66: 02e78633     	mul	a2, a5, a4
      6a: 00279813     	slli	a6, a5, 0x2
      6e: 8d1d         	sub	a0, a0, a5
      70: 95c2         	add	a1, a1, a6
      72: 0ae6e427     	vsse32.v	v8, (a3), a4
      76: 96b2         	add	a3, a3, a2
      78: fea043e3     	bgtz	a0, 0x5e <.L9>
      7c: b77d         	j	0x2a <.L23>

000000000000007e <.L30>:
      7e: 060a         	slli	a2, a2, 0x2

0000000000000080 <.L7>:
      80: 0c1577d7     	vsetvli	a5, a0, e8, m2, ta, ma
      84: 0ac5e407     	vlse32.v	v8, (a1), a2
      88: 02f60733     	mul	a4, a2, a5
      8c: 00279813     	slli	a6, a5, 0x2
      90: 8d1d         	sub	a0, a0, a5
      92: 0206e427     	vse32.v	v8, (a3)
      96: 96c2         	add	a3, a3, a6
      98: 95ba         	add	a1, a1, a4
      9a: fea043e3     	bgtz	a0, 0x80 <.L7>
      9e: 4501         	li	a0, 0x0
      a0: 8082         	ret
