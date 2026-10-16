
ddot_k.o:	file format elf64-littleriscv

Disassembly of section .text:

0000000000000000 <ddot_k>:
       0: f2000553     	fmv.d.x	fa0, zero
       4: 04a05563     	blez	a0, 0x4e <.L23>
       8: 0db07857     	vsetvli	a6, zero, e64, m8, ta, ma
       c: fff60793     	addi	a5, a2, -0x1
      10: 5e003457     	vmv.v.i	v8, 0x0
      14: ef95         	bnez	a5, 0x50 <.L3>
      16: fff70793     	addi	a5, a4, -0x1
      1a: eb9d         	bnez	a5, 0x50 <.L3>

000000000000001c <.L4>:
      1c: 09b577d7     	vsetvli	a5, a0, e64, m8, tu, ma
      20: 0205fc07     	vle64.v	v24, (a1)
      24: 0206f807     	vle64.v	v16, (a3)
      28: 00379713     	slli	a4, a5, 0x3
      2c: 8d1d         	sub	a0, a0, a5
      2e: 95ba         	add	a1, a1, a4
      30: 96ba         	add	a3, a3, a4
      32: b30c1457     	vfmacc.vv	v8, v24, v16
      36: fea043e3     	bgtz	a0, 0x1c <.L4>

000000000000003a <.L5>:
      3a: 0d887057     	vsetvli	zero, a6, e64, m1, ta, ma
      3e: 5e0030d7     	vmv.v.i	v1, 0x0
      42: 0db07857     	vsetvli	a6, zero, e64, m8, ta, ma
      46: 06809457     	vfredusum.vs	v8, v8, v1
      4a: 42801557     	vfmv.f.s	fa0, v8

000000000000004e <.L23>:
      4e: 8082         	ret

0000000000000050 <.L3>:
      50: 4785         	li	a5, 0x1
      52: 04f60b63     	beq	a2, a5, 0xa8 <.L30>
      56: 060e         	slli	a2, a2, 0x3
      58: 00371893     	slli	a7, a4, 0x3
      5c: 02f70463     	beq	a4, a5, 0x84 <.L9>

0000000000000060 <.L10>:
      60: 09b577d7     	vsetvli	a5, a0, e64, m8, tu, ma
      64: 02c78733     	mul	a4, a5, a2
      68: 8d1d         	sub	a0, a0, a5
      6a: 0ac5fc07     	vlse64.v	v24, (a1), a2
      6e: 0b16f807     	vlse64.v	v16, (a3), a7
      72: b30c1457     	vfmacc.vv	v8, v24, v16
      76: 02f887b3     	mul	a5, a7, a5
      7a: 95ba         	add	a1, a1, a4
      7c: 96be         	add	a3, a3, a5
      7e: fea041e3     	bgtz	a0, 0x60 <.L10>
      82: bf65         	j	0x3a <.L5>

0000000000000084 <.L9>:
      84: 09b577d7     	vsetvli	a5, a0, e64, m8, tu, ma
      88: 02c78733     	mul	a4, a5, a2
      8c: 0ac5fc07     	vlse64.v	v24, (a1), a2
      90: 0206f807     	vle64.v	v16, (a3)
      94: 00379893     	slli	a7, a5, 0x3
      98: 8d1d         	sub	a0, a0, a5
      9a: 96c6         	add	a3, a3, a7
      9c: b30c1457     	vfmacc.vv	v8, v24, v16
      a0: 95ba         	add	a1, a1, a4
      a2: fea041e3     	bgtz	a0, 0x84 <.L9>
      a6: bf51         	j	0x3a <.L5>

00000000000000a8 <.L30>:
      a8: 070e         	slli	a4, a4, 0x3

00000000000000aa <.L7>:
      aa: 09b577d7     	vsetvli	a5, a0, e64, m8, tu, ma
      ae: 02f70633     	mul	a2, a4, a5
      b2: 0205fc07     	vle64.v	v24, (a1)
      b6: 0ae6f807     	vlse64.v	v16, (a3), a4
      ba: 00379893     	slli	a7, a5, 0x3
      be: 8d1d         	sub	a0, a0, a5
      c0: 95c6         	add	a1, a1, a7
      c2: b30c1457     	vfmacc.vv	v8, v24, v16
      c6: 96b2         	add	a3, a3, a2
      c8: fea041e3     	bgtz	a0, 0xaa <.L7>
      cc: 0d887057     	vsetvli	zero, a6, e64, m1, ta, ma
      d0: 5e0030d7     	vmv.v.i	v1, 0x0
      d4: 0db07857     	vsetvli	a6, zero, e64, m8, ta, ma
      d8: 06809457     	vfredusum.vs	v8, v8, v1
      dc: 42801557     	vfmv.f.s	fa0, v8
      e0: 8082         	ret
