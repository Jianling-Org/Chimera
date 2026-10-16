Disassembly of section .plt:

00000000000277a0 <*ABS*+0x7ab82@plt>:
   277a0:	00120e17          	auipc	t3,0x120
   277a4:	8e8e3e03          	ld	t3,-1816(t3) # 147088 <.got.plt+0x98>
   277a8:	000e0367          	jalr	t1,t3
   277ac:	00000013          	nop

Disassembly of section .text:

0000000000047a2a <__printf_buffer_write>:
   47a2a:	511c                	lw	a5,32(a0)
   47a2c:	c7c1                	beqz	a5,47ab4 <__printf_buffer_write+0x8a>
   47a2e:	7179                	addi	sp,sp,-48
   47a30:	ec26                	sd	s1,24(sp)
   47a32:	f406                	sd	ra,40(sp)
   47a34:	84b2                	mv	s1,a2
   47a36:	ca3d                	beqz	a2,47aac <__printf_buffer_write+0x82>
   47a38:	e84a                	sd	s2,16(sp)
   47a3a:	e44e                	sd	s3,8(sp)
   47a3c:	892a                	mv	s2,a0
   47a3e:	f022                	sd	s0,32(sp)
   47a40:	6508                	ld	a0,8(a0)
   47a42:	89ae                	mv	s3,a1
   47a44:	a01d                	j	47a6a <__printf_buffer_write+0x40>
   47a46:	8c09                	sub	s0,s0,a0
   47a48:	0084f363          	bgeu	s1,s0,47a4e <__printf_buffer_write+0x24>
   47a4c:	8426                	mv	s0,s1
   47a4e:	85ce                	mv	a1,s3
   47a50:	8622                	mv	a2,s0
   47a52:	8c81                	sub	s1,s1,s0
   47a54:	99a2                	add	s3,s3,s0
   47a56:	fffe0097          	auipc	ra,0xfffe0
   47a5a:	d4a080e7          	jalr	-694(ra) # 277a0 <*ABS*+0x7ab82@plt>
   47a5e:	00893503          	ld	a0,8(s2)
   47a62:	9522                	add	a0,a0,s0
   47a64:	00a93423          	sd	a0,8(s2)
   47a68:	cc9d                	beqz	s1,47aa6 <__printf_buffer_write+0x7c>
   47a6a:	01093403          	ld	s0,16(s2)
   47a6e:	fca41ce3          	bne	s0,a0,47a46 <__printf_buffer_write+0x1c>
   47a72:	854a                	mv	a0,s2
   47a74:	c2bff0ef          	jal	4769e <__printf_buffer_flush>
   47a78:	c51d                	beqz	a0,47aa6 <__printf_buffer_write+0x7c>
   47a7a:	00893503          	ld	a0,8(s2)
   47a7e:	01093403          	ld	s0,16(s2)
   47a82:	fc8512e3          	bne	a0,s0,47a46 <__printf_buffer_write+0x1c>
   47a86:	000c4697          	auipc	a3,0xc4
   47a8a:	56a68693          	addi	a3,a3,1386 # 10bff0 <__PRETTY_FUNCTION__.0>
   47a8e:	02300613          	li	a2,35
   47a92:	000c4597          	auipc	a1,0xc4
   47a96:	54658593          	addi	a1,a1,1350 # 10bfd8 <__PRETTY_FUNCTION__.0+0x20>
   47a9a:	000c4517          	auipc	a0,0xc4
   47a9e:	3e650513          	addi	a0,a0,998 # 10be80 <__PRETTY_FUNCTION__.0+0x38>
   47aa2:	af0ea0ef          	jal	31d92 <__libc_assert_fail>
   47aa6:	7402                	ld	s0,32(sp)
   47aa8:	6942                	ld	s2,16(sp)
   47aaa:	69a2                	ld	s3,8(sp)
   47aac:	70a2                	ld	ra,40(sp)
   47aae:	64e2                	ld	s1,24(sp)
   47ab0:	6145                	addi	sp,sp,48
   47ab2:	8082                	ret
   47ab4:	8082                	ret
