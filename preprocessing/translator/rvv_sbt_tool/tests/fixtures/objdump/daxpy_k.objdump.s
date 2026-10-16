
daxpy_k.o:	file format elf64-littleriscv

Disassembly of section .text:

0000000000000000 <daxpy_k>:
       0: f20007d3     	fmv.d.x	fa5, zero
       4: a2f52653     	feq.d	a2, fa0, fa5
       8: ea15         	bnez	a2, 0x3c <.L33>
       a: 02a05963     	blez	a0, 0x3c <.L33>
       e: fff80613     	addi	a2, a6, -0x1
      12: fff70593     	addi	a1, a4, -0x1
      16: e60d         	bnez	a2, 0x40 <.L5>
      18: e585         	bnez	a1, 0x40 <.L5>

000000000000001a <.L6>:
      1a: 0db57757     	vsetvli	a4, a0, e64, m8, ta, ma
      1e: 0206f807     	vle64.v	v16, (a3)
      22: 0207f407     	vle64.v	v8, (a5)
      26: 00371613     	slli	a2, a4, 0x3
      2a: 8d19         	sub	a0, a0, a4
      2c: 96b2         	add	a3, a3, a2
      2e: b3055457     	vfmacc.vf	v8, fa0, v16
      32: 0207f427     	vse64.v	v8, (a5)
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
      4c: 080e         	slli	a6, a6, 0x3

000000000000004e <.L11>:
      4e: 0db57757     	vsetvli	a4, a0, e64, m8, ta, ma
      52: 0206f807     	vle64.v	v16, (a3)
      56: 0b07f407     	vlse64.v	v8, (a5), a6
      5a: 02e80633     	mul	a2, a6, a4
      5e: 00371593     	slli	a1, a4, 0x3
      62: 8d19         	sub	a0, a0, a4
      64: 96ae         	add	a3, a3, a1
      66: b3055457     	vfmacc.vf	v8, fa0, v16
      6a: 0b07f427     	vsse64.v	v8, (a5), a6
      6e: 97b2         	add	a5, a5, a2
      70: fca04fe3     	bgtz	a0, 0x4e <.L11>
      74: b7e1         	j	0x3c <.L33>

0000000000000076 <.L40>:
      76: 070e         	slli	a4, a4, 0x3

0000000000000078 <.L9>:
      78: 0db57657     	vsetvli	a2, a0, e64, m8, ta, ma
      7c: 0ae6f807     	vlse64.v	v16, (a3), a4
      80: 0207f407     	vle64.v	v8, (a5)
      84: 02c70833     	mul	a6, a4, a2
      88: 00361593     	slli	a1, a2, 0x3
      8c: 8d11         	sub	a0, a0, a2
      8e: b3055457     	vfmacc.vf	v8, fa0, v16
      92: 96c2         	add	a3, a3, a6
      94: 0207f427     	vse64.v	v8, (a5)
      98: 97ae         	add	a5, a5, a1
      9a: fca04fe3     	bgtz	a0, 0x78 <.L9>
      9e: bf79         	j	0x3c <.L33>

00000000000000a0 <.L10>:
      a0: 070e         	slli	a4, a4, 0x3
      a2: 04081963     	bnez	a6, 0xf4 <.L12>
      a6: 0db57857     	vsetvli	a6, a0, e64, m8, ta, ma
      aa: 0ae6f807     	vlse64.v	v16, (a3), a4
      ae: 239c         	fld	fa5, 0x0(a5)
      b0: 41050533     	sub	a0, a0, a6
      b4: 5e07d457     	vfmv.v.f	v8, fa5
      b8: b3055457     	vfmacc.vf	v8, fa0, v16
      bc: 00a05f63     	blez	a0, 0xda <.L13>
      c0: 8642         	mv	a2, a6

00000000000000c2 <.L14>:
      c2: 02e605b3     	mul	a1, a2, a4
      c6: 0db57657     	vsetvli	a2, a0, e64, m8, ta, ma
      ca: 8d11         	sub	a0, a0, a2
      cc: 96ae         	add	a3, a3, a1
      ce: 0ae6f807     	vlse64.v	v16, (a3), a4
      d2: b3055457     	vfmacc.vf	v8, fa0, v16
      d6: fea046e3     	bgtz	a0, 0xc2 <.L14>

00000000000000da <.L13>:
      da: cd80f057     	vsetivli	zero, 0x1, e64, m1, ta, ma
      de: 420060d7     	vmv.s.x	v1, zero
      e2: 0db87057     	vsetvli	zero, a6, e64, m8, ta, ma
      e6: 06809457     	vfredusum.vs	v8, v8, v1
      ea: cd80f057     	vsetivli	zero, 0x1, e64, m1, ta, ma
      ee: 0207f427     	vse64.v	v8, (a5)
      f2: b7a9         	j	0x3c <.L33>

00000000000000f4 <.L12>:
      f4: 080e         	slli	a6, a6, 0x3

00000000000000f6 <.L15>:
      f6: 0db57657     	vsetvli	a2, a0, e64, m8, ta, ma
      fa: 0ae6f807     	vlse64.v	v16, (a3), a4
      fe: 0b07f407     	vlse64.v	v8, (a5), a6
     102: 02e608b3     	mul	a7, a2, a4
     106: 8d11         	sub	a0, a0, a2
     108: b3055457     	vfmacc.vf	v8, fa0, v16
     10c: 02c805b3     	mul	a1, a6, a2
     110: 0b07f427     	vsse64.v	v8, (a5), a6
     114: 96c6         	add	a3, a3, a7
     116: 97ae         	add	a5, a5, a1
     118: fca04fe3     	bgtz	a0, 0xf6 <.L15>
     11c: b705         	j	0x3c <.L33>
