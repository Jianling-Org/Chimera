
tests/fixtures/obj/sswap_k.o:	file format elf64-littleriscv

Disassembly of section .text:

0000000000000000 <sswap_k>:
       0: 00a05f63     	blez	a0, 0x1e <.L39>
       4: 01076633     	or	a2, a4, a6
       8: ee09         	bnez	a2, 0x22 <.L4>
       a: 8905         	andi	a0, a0, 0x1
       c: c909         	beqz	a0, 0x1e <.L39>
       e: 0007a707     	flw	fa4, 0x0(a5)
      12: 0006a787     	flw	fa5, 0x0(a3)
      16: 00e6a027     	fsw	fa4, 0x0(a3)
      1a: 00f7a027     	fsw	fa5, 0x0(a5)

000000000000001e <.L39>:
      1e: 4501         	li	a0, 0x0
      20: 8082         	ret

0000000000000022 <.L4>:
      22: c729         	beqz	a4, 0x6c <.L50>
      24: 08081763     	bnez	a6, 0xb2 <.L10>
      28: 157d         	addi	a0, a0, -0x1
      2a: 02e50633     	mul	a2, a0, a4
      2e: 0007a787     	flw	fa5, 0x0(a5)
      32: 40e00833     	neg	a6, a4
      36: 080a         	slli	a6, a6, 0x2
      38: 060a         	slli	a2, a2, 0x2
      3a: 9636         	add	a2, a2, a3
      3c: 00062707     	flw	fa4, 0x0(a2)
      40: 00e7a027     	fsw	fa4, 0x0(a5)
      44: c10d         	beqz	a0, 0x66 <.L13>

0000000000000046 <.L12>:
      46: 0c1577d7     	vsetvli	a5, a0, e8, m2, ta, ma
      4a: ffc60593     	addi	a1, a2, -0x4
      4e: 0b05e407     	vlse32.v	v8, (a1), a6
      52: 02f705b3     	mul	a1, a4, a5
      56: 8d1d         	sub	a0, a0, a5
      58: 0b066427     	vsse32.v	v8, (a2), a6
      5c: 00259793     	slli	a5, a1, 0x2
      60: 8e1d         	sub	a2, a2, a5
      62: fea042e3     	bgtz	a0, 0x46 <.L12>

0000000000000066 <.L13>:
      66: 00f6a027     	fsw	fa5, 0x0(a3)
      6a: bf55         	j	0x1e <.L39>

000000000000006c <.L50>:
      6c: 157d         	addi	a0, a0, -0x1
      6e: 03050633     	mul	a2, a0, a6
      72: 0006a787     	flw	fa5, 0x0(a3)
      76: 410005b3     	neg	a1, a6
      7a: 058a         	slli	a1, a1, 0x2
      7c: 060a         	slli	a2, a2, 0x2
      7e: 963e         	add	a2, a2, a5
      80: 00062707     	flw	fa4, 0x0(a2)
      84: 00e6a027     	fsw	fa4, 0x0(a3)
      88: c10d         	beqz	a0, 0xaa <.L9>

000000000000008a <.L8>:
      8a: 0c157757     	vsetvli	a4, a0, e8, m2, ta, ma
      8e: ffc60693     	addi	a3, a2, -0x4
      92: 0ab6e407     	vlse32.v	v8, (a3), a1
      96: 02e806b3     	mul	a3, a6, a4
      9a: 8d19         	sub	a0, a0, a4
      9c: 0ab66427     	vsse32.v	v8, (a2), a1
      a0: 00269713     	slli	a4, a3, 0x2
      a4: 8e19         	sub	a2, a2, a4
      a6: fea042e3     	bgtz	a0, 0x8a <.L8>

00000000000000aa <.L9>:
      aa: 00f7a027     	fsw	fa5, 0x0(a5)
      ae: 4501         	li	a0, 0x0
      b0: 8082         	ret

00000000000000b2 <.L10>:
      b2: fff70613     	addi	a2, a4, -0x1
      b6: e615         	bnez	a2, 0xe2 <.L14>
      b8: fff80613     	addi	a2, a6, -0x1
      bc: e21d         	bnez	a2, 0xe2 <.L14>

00000000000000be <.L15>:
      be: 0c157757     	vsetvli	a4, a0, e8, m2, ta, ma
      c2: 0206e807     	vle32.v	v16, (a3)
      c6: 0207e407     	vle32.v	v8, (a5)
      ca: 00271613     	slli	a2, a4, 0x2
      ce: 8d19         	sub	a0, a0, a4
      d0: 0207e827     	vse32.v	v16, (a5)
      d4: 97b2         	add	a5, a5, a2
      d6: 0206e427     	vse32.v	v8, (a3)
      da: 96b2         	add	a3, a3, a2
      dc: fea041e3     	bgtz	a0, 0xbe <.L15>
      e0: bf3d         	j	0x1e <.L39>

00000000000000e2 <.L14>:
      e2: 4585         	li	a1, 0x1
      e4: 04b80f63     	beq	a6, a1, 0x142 <.L51>
      e8: 080a         	slli	a6, a6, 0x2
      ea: 00271613     	slli	a2, a4, 0x2
      ee: 02b70663     	beq	a4, a1, 0x11a <.L19>

00000000000000f2 <.L20>:
      f2: 0c157757     	vsetvli	a4, a0, e8, m2, ta, ma
      f6: 0ac6e807     	vlse32.v	v16, (a3), a2
      fa: 0b07e407     	vlse32.v	v8, (a5), a6
      fe: 02e608b3     	mul	a7, a2, a4
     102: 8d19         	sub	a0, a0, a4
     104: 0b07e827     	vsse32.v	v16, (a5), a6
     108: 030705b3     	mul	a1, a4, a6
     10c: 0ac6e427     	vsse32.v	v8, (a3), a2
     110: 96c6         	add	a3, a3, a7
     112: 97ae         	add	a5, a5, a1
     114: fca04fe3     	bgtz	a0, 0xf2 <.L20>
     118: b719         	j	0x1e <.L39>

000000000000011a <.L19>:
     11a: 0c157757     	vsetvli	a4, a0, e8, m2, ta, ma
     11e: 0206e807     	vle32.v	v16, (a3)
     122: 0b07e407     	vlse32.v	v8, (a5), a6
     126: 030705b3     	mul	a1, a4, a6
     12a: 00271613     	slli	a2, a4, 0x2
     12e: 8d19         	sub	a0, a0, a4
     130: 0b07e827     	vsse32.v	v16, (a5), a6
     134: 0206e427     	vse32.v	v8, (a3)
     138: 97ae         	add	a5, a5, a1
     13a: 96b2         	add	a3, a3, a2
     13c: fca04fe3     	bgtz	a0, 0x11a <.L19>
     140: bdf9         	j	0x1e <.L39>

0000000000000142 <.L51>:
     142: 070a         	slli	a4, a4, 0x2

0000000000000144 <.L17>:
     144: 0c157657     	vsetvli	a2, a0, e8, m2, ta, ma
     148: 0ae6e807     	vlse32.v	v16, (a3), a4
     14c: 0207e407     	vle32.v	v8, (a5)
     150: 02c705b3     	mul	a1, a4, a2
     154: 00261813     	slli	a6, a2, 0x2
     158: 8d11         	sub	a0, a0, a2
     15a: 0207e827     	vse32.v	v16, (a5)
     15e: 97c2         	add	a5, a5, a6
     160: 0ae6e427     	vsse32.v	v8, (a3), a4
     164: 96ae         	add	a3, a3, a1
     166: fca04fe3     	bgtz	a0, 0x144 <.L17>
     16a: bd55         	j	0x1e <.L39>
