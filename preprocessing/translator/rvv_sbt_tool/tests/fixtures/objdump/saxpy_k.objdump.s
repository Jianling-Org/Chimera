
tests/fixtures/obj/saxpy_k.o:	file format elf64-littleriscv

Disassembly of section .text:

0000000000000000 <saxpy_k>:
       0: f00007d3     	fmv.w.x	fa5, zero
       4: a0f52653     	feq.s	a2, fa0, fa5
       8: ea15         	bnez	a2, 0x3c <.L33>
       a: 02a05963     	blez	a0, 0x3c <.L33>
       e: fff80613     	addi	a2, a6, -0x1
      12: fff70593     	addi	a1, a4, -0x1
      16: e60d         	bnez	a2, 0x40 <.L5>
      18: e585         	bnez	a1, 0x40 <.L5>

000000000000001a <.L6>:
      1a: 0d357757     	vsetvli	a4, a0, e32, m8, ta, ma
      1e: 0206e807     	vle32.v	v16, (a3)
      22: 0207e407     	vle32.v	v8, (a5)
      26: 00271613     	slli	a2, a4, 0x2
      2a: 8d19         	sub	a0, a0, a4
      2c: 96b2         	add	a3, a3, a2
      2e: b3055457     	vfmacc.vf	v8, fa0, v16
      32: 0207e427     	vse32.v	v8, (a5)
      36: 97b2         	add	a5, a5, a2
      38: fea041e3     	bgtz	a0, 0x1a <.L6>

000000000000003c <.L33>:
      3c: 4501         	li	a0, 0x0
      3e: 8082         	ret

0000000000000040 <.L5>:
      40: 4605         	li	a2, 0x1
      42: 02c80a63     	beq	a6, a2, 0x76 <.L40>
      46: 04080d63     	beqz	a6, 0xa0 <.L10>
      4a: e9b9         	bnez	a1, 0xa0 <.L10>
      4c: 080a         	slli	a6, a6, 0x2

000000000000004e <.L11>:
      4e: 0d357757     	vsetvli	a4, a0, e32, m8, ta, ma
      52: 0206e807     	vle32.v	v16, (a3)
      56: 0b07e407     	vlse32.v	v8, (a5), a6
      5a: 02e80633     	mul	a2, a6, a4
      5e: 00271593     	slli	a1, a4, 0x2
      62: 8d19         	sub	a0, a0, a4
      64: 96ae         	add	a3, a3, a1
      66: b3055457     	vfmacc.vf	v8, fa0, v16
      6a: 0b07e427     	vsse32.v	v8, (a5), a6
      6e: 97b2         	add	a5, a5, a2
      70: fca04fe3     	bgtz	a0, 0x4e <.L11>
      74: b7e1         	j	0x3c <.L33>

0000000000000076 <.L40>:
      76: 070a         	slli	a4, a4, 0x2

0000000000000078 <.L9>:
      78: 0d357657     	vsetvli	a2, a0, e32, m8, ta, ma
      7c: 0ae6e807     	vlse32.v	v16, (a3), a4
      80: 0207e407     	vle32.v	v8, (a5)
      84: 02c70833     	mul	a6, a4, a2
      88: 00261593     	slli	a1, a2, 0x2
      8c: 8d11         	sub	a0, a0, a2
      8e: b3055457     	vfmacc.vf	v8, fa0, v16
      92: 96c2         	add	a3, a3, a6
      94: 0207e427     	vse32.v	v8, (a5)
      98: 97ae         	add	a5, a5, a1
      9a: fca04fe3     	bgtz	a0, 0x78 <.L9>
      9e: bf79         	j	0x3c <.L33>

00000000000000a0 <.L10>:
      a0: 070a         	slli	a4, a4, 0x2
      a2: 04081a63     	bnez	a6, 0xf6 <.L12>
      a6: 0d357857     	vsetvli	a6, a0, e32, m8, ta, ma
      aa: 0ae6e807     	vlse32.v	v16, (a3), a4
      ae: 0007a787     	flw	fa5, 0x0(a5)
      b2: 41050533     	sub	a0, a0, a6
      b6: 5e07d457     	vfmv.v.f	v8, fa5
      ba: b3055457     	vfmacc.vf	v8, fa0, v16
      be: 00a05f63     	blez	a0, 0xdc <.L13>
      c2: 8642         	mv	a2, a6

00000000000000c4 <.L14>:
      c4: 02e605b3     	mul	a1, a2, a4
      c8: 0d357657     	vsetvli	a2, a0, e32, m8, ta, ma
      cc: 8d11         	sub	a0, a0, a2
      ce: 96ae         	add	a3, a3, a1
      d0: 0ae6e807     	vlse32.v	v16, (a3), a4
      d4: b3055457     	vfmacc.vf	v8, fa0, v16
      d8: fea046e3     	bgtz	a0, 0xc4 <.L14>

00000000000000dc <.L13>:
      dc: cd00f057     	vsetivli	zero, 0x1, e32, m1, ta, ma
      e0: 420060d7     	vmv.s.x	v1, zero
      e4: 0d387057     	vsetvli	zero, a6, e32, m8, ta, ma
      e8: 06809457     	vfredusum.vs	v8, v8, v1
      ec: cd00f057     	vsetivli	zero, 0x1, e32, m1, ta, ma
      f0: 0207e427     	vse32.v	v8, (a5)
      f4: b7a1         	j	0x3c <.L33>

00000000000000f6 <.L12>:
      f6: 080a         	slli	a6, a6, 0x2

00000000000000f8 <.L15>:
      f8: 0d357657     	vsetvli	a2, a0, e32, m8, ta, ma
      fc: 0ae6e807     	vlse32.v	v16, (a3), a4
     100: 0b07e407     	vlse32.v	v8, (a5), a6
     104: 02e608b3     	mul	a7, a2, a4
     108: 8d11         	sub	a0, a0, a2
     10a: b3055457     	vfmacc.vf	v8, fa0, v16
     10e: 02c805b3     	mul	a1, a6, a2
     112: 0b07e427     	vsse32.v	v8, (a5), a6
     116: 96c6         	add	a3, a3, a7
     118: 97ae         	add	a5, a5, a1
     11a: fca04fe3     	bgtz	a0, 0xf8 <.L15>
     11e: bf39         	j	0x3c <.L33>
