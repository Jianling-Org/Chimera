
tests/fixtures/obj/sdot_k.o:	file format elf64-littleriscv

Disassembly of section .text:

0000000000000000 <sdot_k>:
       0: f0000553     	fmv.w.x	fa0, zero
       4: 04a05763     	blez	a0, 0x52 <.L23>
       8: 0db07857     	vsetvli	a6, zero, e64, m8, ta, ma
       c: fff60793     	addi	a5, a2, -0x1
      10: 5e003857     	vmv.v.i	v16, 0x0
      14: e3a1         	bnez	a5, 0x54 <.L3>
      16: fff70793     	addi	a5, a4, -0x1
      1a: ef8d         	bnez	a5, 0x54 <.L3>

000000000000001c <.L4>:
      1c: 092577d7     	vsetvli	a5, a0, e32, m4, tu, ma
      20: 0205e407     	vle32.v	v8, (a1)
      24: 0206e207     	vle32.v	v4, (a3)
      28: 00279713     	slli	a4, a5, 0x2
      2c: 8d1d         	sub	a0, a0, a5
      2e: 95ba         	add	a1, a1, a4
      30: 96ba         	add	a3, a3, a4
      32: f2441857     	vfwmacc.vv	v16, v8, v4
      36: fea043e3     	bgtz	a0, 0x1c <.L4>

000000000000003a <.L5>:
      3a: 0d887057     	vsetvli	zero, a6, e64, m1, ta, ma
      3e: 5e0030d7     	vmv.v.i	v1, 0x0
      42: 0db07857     	vsetvli	a6, zero, e64, m8, ta, ma
      46: 070090d7     	vfredusum.vs	v1, v16, v1
      4a: 42101557     	vfmv.f.s	fa0, v1
      4e: 40157553     	fcvt.s.d	fa0, fa0

0000000000000052 <.L23>:
      52: 8082         	ret

0000000000000054 <.L3>:
      54: 4785         	li	a5, 0x1
      56: 04f60b63     	beq	a2, a5, 0xac <.L30>
      5a: 060a         	slli	a2, a2, 0x2
      5c: 00271893     	slli	a7, a4, 0x2
      60: 02f70463     	beq	a4, a5, 0x88 <.L9>

0000000000000064 <.L10>:
      64: 092577d7     	vsetvli	a5, a0, e32, m4, tu, ma
      68: 02c78733     	mul	a4, a5, a2
      6c: 8d1d         	sub	a0, a0, a5
      6e: 0ac5e407     	vlse32.v	v8, (a1), a2
      72: 0b16e207     	vlse32.v	v4, (a3), a7
      76: f2441857     	vfwmacc.vv	v16, v8, v4
      7a: 02f887b3     	mul	a5, a7, a5
      7e: 95ba         	add	a1, a1, a4
      80: 96be         	add	a3, a3, a5
      82: fea041e3     	bgtz	a0, 0x64 <.L10>
      86: bf55         	j	0x3a <.L5>

0000000000000088 <.L9>:
      88: 092577d7     	vsetvli	a5, a0, e32, m4, tu, ma
      8c: 02c78733     	mul	a4, a5, a2
      90: 0ac5e407     	vlse32.v	v8, (a1), a2
      94: 0206e207     	vle32.v	v4, (a3)
      98: 00279893     	slli	a7, a5, 0x2
      9c: 8d1d         	sub	a0, a0, a5
      9e: 96c6         	add	a3, a3, a7
      a0: f2441857     	vfwmacc.vv	v16, v8, v4
      a4: 95ba         	add	a1, a1, a4
      a6: fea041e3     	bgtz	a0, 0x88 <.L9>
      aa: bf41         	j	0x3a <.L5>

00000000000000ac <.L30>:
      ac: 070a         	slli	a4, a4, 0x2

00000000000000ae <.L7>:
      ae: 092577d7     	vsetvli	a5, a0, e32, m4, tu, ma
      b2: 02f70633     	mul	a2, a4, a5
      b6: 0205e407     	vle32.v	v8, (a1)
      ba: 0ae6e207     	vlse32.v	v4, (a3), a4
      be: 00279893     	slli	a7, a5, 0x2
      c2: 8d1d         	sub	a0, a0, a5
      c4: 95c6         	add	a1, a1, a7
      c6: f2441857     	vfwmacc.vv	v16, v8, v4
      ca: 96b2         	add	a3, a3, a2
      cc: fea041e3     	bgtz	a0, 0xae <.L7>
      d0: 0d887057     	vsetvli	zero, a6, e64, m1, ta, ma
      d4: 5e0030d7     	vmv.v.i	v1, 0x0
      d8: 0db07857     	vsetvli	a6, zero, e64, m8, ta, ma
      dc: 070090d7     	vfredusum.vs	v1, v16, v1
      e0: 42101557     	vfmv.f.s	fa0, v1
      e4: 40157553     	fcvt.s.d	fa0, fa0
      e8: 8082         	ret
