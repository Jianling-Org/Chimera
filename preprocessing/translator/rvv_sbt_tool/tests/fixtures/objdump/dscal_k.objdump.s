
dscal_k.o:	file format elf64-littleriscv

Disassembly of section .text:

0000000000000000 <dscal_k>:
       0: 02a05f63     	blez	a0, 0x3e <.L19>
       4: 02e05d63     	blez	a4, 0x3e <.L19>
       8: f20007d3     	fmv.d.x	fa5, zero
       c: 6782         	ld	a5, 0x0(sp)
       e: 4605         	li	a2, 0x1
      10: a2f525d3     	feq.d	a1, fa0, fa5
      14: 0017b793     	seqz	a5, a5
      18: 8fed         	and	a5, a5, a1
      1a: 06c70163     	beq	a4, a2, 0x7c <.L29>
      1e: 070e         	slli	a4, a4, 0x3
      20: c38d         	beqz	a5, 0x42 <.L8>
      22: 0db077d7     	vsetvli	a5, zero, e64, m8, ta, ma
      26: 5e003457     	vmv.v.i	v8, 0x0

000000000000002a <.L9>:
      2a: 0c0577d7     	vsetvli	a5, a0, e8, m1, ta, ma
      2e: 02f70633     	mul	a2, a4, a5
      32: 0ae6f427     	vsse64.v	v8, (a3), a4
      36: 8d1d         	sub	a0, a0, a5
      38: 96b2         	add	a3, a3, a2
      3a: fea048e3     	bgtz	a0, 0x2a <.L9>

000000000000003e <.L19>:
      3e: 4501         	li	a0, 0x0
      40: 8082         	ret

0000000000000042 <.L8>:
      42: 0db577d7     	vsetvli	a5, a0, e64, m8, ta, ma
      46: 0ae6f407     	vlse64.v	v8, (a3), a4
      4a: 02f70633     	mul	a2, a4, a5
      4e: 8d1d         	sub	a0, a0, a5
      50: 92855457     	vfmul.vf	v8, v8, fa0
      54: 0ae6f427     	vsse64.v	v8, (a3), a4
      58: 96b2         	add	a3, a3, a2
      5a: fea052e3     	blez	a0, 0x3e <.L19>
      5e: 0db577d7     	vsetvli	a5, a0, e64, m8, ta, ma
      62: 0ae6f407     	vlse64.v	v8, (a3), a4
      66: 02f70633     	mul	a2, a4, a5
      6a: 8d1d         	sub	a0, a0, a5
      6c: 92855457     	vfmul.vf	v8, v8, fa0
      70: 0ae6f427     	vsse64.v	v8, (a3), a4
      74: 96b2         	add	a3, a3, a2
      76: fca046e3     	bgtz	a0, 0x42 <.L8>
      7a: b7d1         	j	0x3e <.L19>

000000000000007c <.L29>:
      7c: c385         	beqz	a5, 0x9c <.L5>
      7e: 0db077d7     	vsetvli	a5, zero, e64, m8, ta, ma
      82: 5e003457     	vmv.v.i	v8, 0x0

0000000000000086 <.L6>:
      86: 0c0577d7     	vsetvli	a5, a0, e8, m1, ta, ma
      8a: 0206f427     	vse64.v	v8, (a3)
      8e: 8d1d         	sub	a0, a0, a5
      90: 078e         	slli	a5, a5, 0x3
      92: 96be         	add	a3, a3, a5
      94: fea049e3     	bgtz	a0, 0x86 <.L6>
      98: 4501         	li	a0, 0x0
      9a: 8082         	ret

000000000000009c <.L5>:
      9c: 0db577d7     	vsetvli	a5, a0, e64, m8, ta, ma
      a0: 0206f407     	vle64.v	v8, (a3)
      a4: 00379713     	slli	a4, a5, 0x3
      a8: 8d1d         	sub	a0, a0, a5
      aa: 92855457     	vfmul.vf	v8, v8, fa0
      ae: 0206f427     	vse64.v	v8, (a3)
      b2: 96ba         	add	a3, a3, a4
      b4: f8a055e3     	blez	a0, 0x3e <.L19>
      b8: 0db577d7     	vsetvli	a5, a0, e64, m8, ta, ma
      bc: 0206f407     	vle64.v	v8, (a3)
      c0: 00379713     	slli	a4, a5, 0x3
      c4: 8d1d         	sub	a0, a0, a5
      c6: 92855457     	vfmul.vf	v8, v8, fa0
      ca: 0206f427     	vse64.v	v8, (a3)
      ce: 96ba         	add	a3, a3, a4
      d0: fca046e3     	bgtz	a0, 0x9c <.L5>
      d4: b7ad         	j	0x3e <.L19>
