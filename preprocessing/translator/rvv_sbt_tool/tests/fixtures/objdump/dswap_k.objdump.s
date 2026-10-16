
dswap_k.o:	file format elf64-littleriscv

Disassembly of section .text:

0000000000000000 <dswap_k>:
       0: 00a05b63     	blez	a0, 0x16 <.L39>
       4: 01076633     	or	a2, a4, a6
       8: ea09         	bnez	a2, 0x1a <.L4>
       a: 8905         	andi	a0, a0, 0x1
       c: c509         	beqz	a0, 0x16 <.L39>
       e: 2398         	fld	fa4, 0x0(a5)
      10: 229c         	fld	fa5, 0x0(a3)
      12: a298         	fsd	fa4, 0x0(a3)
      14: a39c         	fsd	fa5, 0x0(a5)

0000000000000016 <.L39>:
      16: 4501         	li	a0, 0x0
      18: 8082         	ret

000000000000001a <.L4>:
      1a: c329         	beqz	a4, 0x5c <.L50>
      1c: 06081f63     	bnez	a6, 0x9a <.L10>
      20: 157d         	addi	a0, a0, -0x1
      22: 02e50633     	mul	a2, a0, a4
      26: 239c         	fld	fa5, 0x0(a5)
      28: 40e00833     	neg	a6, a4
      2c: 080e         	slli	a6, a6, 0x3
      2e: 060e         	slli	a2, a2, 0x3
      30: 9636         	add	a2, a2, a3
      32: 2218         	fld	fa4, 0x0(a2)
      34: a398         	fsd	fa4, 0x0(a5)
      36: c10d         	beqz	a0, 0x58 <.L13>

0000000000000038 <.L12>:
      38: 0c0577d7     	vsetvli	a5, a0, e8, m1, ta, ma
      3c: ff860593     	addi	a1, a2, -0x8
      40: 0b05f407     	vlse64.v	v8, (a1), a6
      44: 02f705b3     	mul	a1, a4, a5
      48: 8d1d         	sub	a0, a0, a5
      4a: 0b067427     	vsse64.v	v8, (a2), a6
      4e: 00359793     	slli	a5, a1, 0x3
      52: 8e1d         	sub	a2, a2, a5
      54: fea042e3     	bgtz	a0, 0x38 <.L12>

0000000000000058 <.L13>:
      58: a29c         	fsd	fa5, 0x0(a3)
      5a: bf75         	j	0x16 <.L39>

000000000000005c <.L50>:
      5c: 157d         	addi	a0, a0, -0x1
      5e: 03050633     	mul	a2, a0, a6
      62: 229c         	fld	fa5, 0x0(a3)
      64: 410005b3     	neg	a1, a6
      68: 058e         	slli	a1, a1, 0x3
      6a: 060e         	slli	a2, a2, 0x3
      6c: 963e         	add	a2, a2, a5
      6e: 2218         	fld	fa4, 0x0(a2)
      70: a298         	fsd	fa4, 0x0(a3)
      72: c10d         	beqz	a0, 0x94 <.L9>

0000000000000074 <.L8>:
      74: 0c057757     	vsetvli	a4, a0, e8, m1, ta, ma
      78: ff860693     	addi	a3, a2, -0x8
      7c: 0ab6f407     	vlse64.v	v8, (a3), a1
      80: 02e806b3     	mul	a3, a6, a4
      84: 8d19         	sub	a0, a0, a4
      86: 0ab67427     	vsse64.v	v8, (a2), a1
      8a: 00369713     	slli	a4, a3, 0x3
      8e: 8e19         	sub	a2, a2, a4
      90: fea042e3     	bgtz	a0, 0x74 <.L8>

0000000000000094 <.L9>:
      94: a39c         	fsd	fa5, 0x0(a5)
      96: 4501         	li	a0, 0x0
      98: 8082         	ret

000000000000009a <.L10>:
      9a: fff70613     	addi	a2, a4, -0x1
      9e: e615         	bnez	a2, 0xca <.L14>
      a0: fff80613     	addi	a2, a6, -0x1
      a4: e21d         	bnez	a2, 0xca <.L14>

00000000000000a6 <.L15>:
      a6: 0c057757     	vsetvli	a4, a0, e8, m1, ta, ma
      aa: 0206f807     	vle64.v	v16, (a3)
      ae: 0207f407     	vle64.v	v8, (a5)
      b2: 00371613     	slli	a2, a4, 0x3
      b6: 8d19         	sub	a0, a0, a4
      b8: 0207f827     	vse64.v	v16, (a5)
      bc: 97b2         	add	a5, a5, a2
      be: 0206f427     	vse64.v	v8, (a3)
      c2: 96b2         	add	a3, a3, a2
      c4: fea041e3     	bgtz	a0, 0xa6 <.L15>
      c8: b7b9         	j	0x16 <.L39>

00000000000000ca <.L14>:
      ca: 4585         	li	a1, 0x1
      cc: 04b80f63     	beq	a6, a1, 0x12a <.L51>
      d0: 080e         	slli	a6, a6, 0x3
      d2: 00371613     	slli	a2, a4, 0x3
      d6: 02b70663     	beq	a4, a1, 0x102 <.L19>

00000000000000da <.L20>:
      da: 0c057757     	vsetvli	a4, a0, e8, m1, ta, ma
      de: 0ac6f807     	vlse64.v	v16, (a3), a2
      e2: 0b07f407     	vlse64.v	v8, (a5), a6
      e6: 02e608b3     	mul	a7, a2, a4
      ea: 8d19         	sub	a0, a0, a4
      ec: 0b07f827     	vsse64.v	v16, (a5), a6
      f0: 030705b3     	mul	a1, a4, a6
      f4: 0ac6f427     	vsse64.v	v8, (a3), a2
      f8: 96c6         	add	a3, a3, a7
      fa: 97ae         	add	a5, a5, a1
      fc: fca04fe3     	bgtz	a0, 0xda <.L20>
     100: bf19         	j	0x16 <.L39>

0000000000000102 <.L19>:
     102: 0c057757     	vsetvli	a4, a0, e8, m1, ta, ma
     106: 0206f807     	vle64.v	v16, (a3)
     10a: 0b07f407     	vlse64.v	v8, (a5), a6
     10e: 030705b3     	mul	a1, a4, a6
     112: 00371613     	slli	a2, a4, 0x3
     116: 8d19         	sub	a0, a0, a4
     118: 0b07f827     	vsse64.v	v16, (a5), a6
     11c: 0206f427     	vse64.v	v8, (a3)
     120: 97ae         	add	a5, a5, a1
     122: 96b2         	add	a3, a3, a2
     124: fca04fe3     	bgtz	a0, 0x102 <.L19>
     128: b5fd         	j	0x16 <.L39>

000000000000012a <.L51>:
     12a: 070e         	slli	a4, a4, 0x3

000000000000012c <.L17>:
     12c: 0c057657     	vsetvli	a2, a0, e8, m1, ta, ma
     130: 0ae6f807     	vlse64.v	v16, (a3), a4
     134: 0207f407     	vle64.v	v8, (a5)
     138: 02c705b3     	mul	a1, a4, a2
     13c: 00361813     	slli	a6, a2, 0x3
     140: 8d11         	sub	a0, a0, a2
     142: 0207f827     	vse64.v	v16, (a5)
     146: 97c2         	add	a5, a5, a6
     148: 0ae6f427     	vsse64.v	v8, (a3), a4
     14c: 96ae         	add	a3, a3, a1
     14e: fca04fe3     	bgtz	a0, 0x12c <.L17>
     152: b5d1         	j	0x16 <.L39>
