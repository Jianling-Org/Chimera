
tests/fixtures/obj/zaxpy_k.o:	file format elf64-littleriscv

Disassembly of section .text:

0000000000000000 <zaxpy_k>:
       0: 06054063     	bltz	a0, 0x60 <.L39>
       4: f20007d3     	fmv.d.x	fa5, zero
       8: a2f52653     	feq.d	a2, fa0, fa5
       c: c601         	beqz	a2, 0x14 <.L12>
       e: a2f5a653     	feq.d	a2, fa1, fa5
      12: e639         	bnez	a2, 0x60 <.L39>

0000000000000014 <.L12>:
      14: fff70613     	addi	a2, a4, -0x1
      18: e631         	bnez	a2, 0x64 <.L5>
      1a: fff80613     	addi	a2, a6, -0x1
      1e: e239         	bnez	a2, 0x64 <.L5>
      20: c121         	beqz	a0, 0x60 <.L39>

0000000000000022 <.L6>:
      22: 0da57757     	vsetvli	a4, a0, e64, m4, ta, ma
      26: 2207f407     	vlseg2e64.v	v8, (a5)
      2a: 2206f807     	vlseg2e64.v	v16, (a3)
      2e: 00471613     	slli	a2, a4, 0x4
      32: 8d19         	sub	a0, a0, a4
      34: 96b2         	add	a3, a3, a2
      36: 9e81b257     	vmv4r.v	v4, v8
      3a: 9ec1bc57     	vmv4r.v	v24, v12
      3e: b3055257     	vfmacc.vf	v4, fa0, v16
      42: b3455c57     	vfmacc.vf	v24, fa0, v20
      46: bf45d257     	vfnmsac.vf	v4, fa1, v20
      4a: b305dc57     	vfmacc.vf	v24, fa1, v16
      4e: 9e41b457     	vmv4r.v	v8, v4
      52: 9f81b657     	vmv4r.v	v12, v24
      56: 2207f427     	vsseg2e64.v	v8, (a5)
      5a: 97b2         	add	a5, a5, a2
      5c: fca043e3     	bgtz	a0, 0x22 <.L6>

0000000000000060 <.L39>:
      60: 4501         	li	a0, 0x0
      62: 8082         	ret

0000000000000064 <.L5>:
      64: 4605         	li	a2, 0x1
      66: 04c70963     	beq	a4, a2, 0xb8 <.L45>
      6a: 0712         	slli	a4, a4, 0x4
      6c: 08c80a63     	beq	a6, a2, 0x100 <.L46>
      70: d965         	beqz	a0, 0x60 <.L39>
      72: 0812         	slli	a6, a6, 0x4

0000000000000074 <.L11>:
      74: 0da57657     	vsetvli	a2, a0, e64, m4, ta, ma
      78: 2b07f407     	vlsseg2e64.v	v8, (a5), a6
      7c: 2ae6f807     	vlsseg2e64.v	v16, (a3), a4
      80: 02e608b3     	mul	a7, a2, a4
      84: 8d11         	sub	a0, a0, a2
      86: 9e81b257     	vmv4r.v	v4, v8
      8a: 9ec1bc57     	vmv4r.v	v24, v12
      8e: 02c805b3     	mul	a1, a6, a2
      92: b3055257     	vfmacc.vf	v4, fa0, v16
      96: b3455c57     	vfmacc.vf	v24, fa0, v20
      9a: 96c6         	add	a3, a3, a7
      9c: bf45d257     	vfnmsac.vf	v4, fa1, v20
      a0: b305dc57     	vfmacc.vf	v24, fa1, v16
      a4: 9e41b457     	vmv4r.v	v8, v4
      a8: 9f81b657     	vmv4r.v	v12, v24
      ac: 2b07f427     	vssseg2e64.v	v8, (a5), a6
      b0: 97ae         	add	a5, a5, a1
      b2: fca041e3     	bgtz	a0, 0x74 <.L11>
      b6: b76d         	j	0x60 <.L39>

00000000000000b8 <.L45>:
      b8: d545         	beqz	a0, 0x60 <.L39>
      ba: 0812         	slli	a6, a6, 0x4

00000000000000bc <.L8>:
      bc: 0da57757     	vsetvli	a4, a0, e64, m4, ta, ma
      c0: 2b07f407     	vlsseg2e64.v	v8, (a5), a6
      c4: 2206f807     	vlseg2e64.v	v16, (a3)
      c8: 02e80633     	mul	a2, a6, a4
      cc: 00471593     	slli	a1, a4, 0x4
      d0: 8d19         	sub	a0, a0, a4
      d2: 96ae         	add	a3, a3, a1
      d4: 9e81b257     	vmv4r.v	v4, v8
      d8: 9ec1bc57     	vmv4r.v	v24, v12
      dc: b3055257     	vfmacc.vf	v4, fa0, v16
      e0: b3455c57     	vfmacc.vf	v24, fa0, v20
      e4: bf45d257     	vfnmsac.vf	v4, fa1, v20
      e8: b305dc57     	vfmacc.vf	v24, fa1, v16
      ec: 9e41b457     	vmv4r.v	v8, v4
      f0: 9f81b657     	vmv4r.v	v12, v24
      f4: 2b07f427     	vssseg2e64.v	v8, (a5), a6
      f8: 97b2         	add	a5, a5, a2
      fa: fca041e3     	bgtz	a0, 0xbc <.L8>
      fe: b78d         	j	0x60 <.L39>

0000000000000100 <.L46>:
     100: d125         	beqz	a0, 0x60 <.L39>

0000000000000102 <.L10>:
     102: 0da57657     	vsetvli	a2, a0, e64, m4, ta, ma
     106: 2207f407     	vlseg2e64.v	v8, (a5)
     10a: 2ae6f807     	vlsseg2e64.v	v16, (a3), a4
     10e: 02e60833     	mul	a6, a2, a4
     112: 00461593     	slli	a1, a2, 0x4
     116: 8d11         	sub	a0, a0, a2
     118: 9e81b257     	vmv4r.v	v4, v8
     11c: 9ec1bc57     	vmv4r.v	v24, v12
     120: 96c2         	add	a3, a3, a6
     122: b3055257     	vfmacc.vf	v4, fa0, v16
     126: b3455c57     	vfmacc.vf	v24, fa0, v20
     12a: bf45d257     	vfnmsac.vf	v4, fa1, v20
     12e: b305dc57     	vfmacc.vf	v24, fa1, v16
     132: 9e41b457     	vmv4r.v	v8, v4
     136: 9f81b657     	vmv4r.v	v12, v24
     13a: 2207f427     	vsseg2e64.v	v8, (a5)
     13e: 97ae         	add	a5, a5, a1
     140: fca041e3     	bgtz	a0, 0x102 <.L10>
     144: bf31         	j	0x60 <.L39>
