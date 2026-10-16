"""Disassembly fixture for the gate-2 ``xgcc`` stack diagnostic.

The five functions below are the exact machine code of ``build-gate2/gcc/xgcc``
at the addresses the stack diagnostic reported them at: instruction addresses,
machine code and function boundaries are verbatim.  Only the DWARF
source-location comments and the absolute build path of the dump header were
removed, so the fixture depends on neither the build directory, the desktop
evidence archive, nor a K3 machine: it runs anywhere the package is
importable.

``_STUB_CALLEE_DUMP`` is *not* evidence.  It is a two-instruction body - one
unresolved indirect ``jalr`` plus a ``ret`` - placed at the ``concat`` target
address used by ``_ZL13close_at_filev``.  It exists so that the real call site
has an internal target, which is what lets the inherited-closure propagation be
exercised end to end: the stub inherits the caller's live VLEN frame state, and
its own unresolved call reproduces the exact finding shape the gate-2 check
reported (an inherited call whose witness path ends at the ``close_at_file``
seed).
"""

from __future__ import annotations

import tempfile
from functools import lru_cache
from pathlib import Path

#: The function with a fixed prologue followed by a dynamic stack allocation
#: whose size is derived from a memory load, a vectorised loop, and a proven
#: frame restore.
CLOSE_AT_FILE = "_ZL13close_at_filev"

#: The four functions whose stack frame is completely fixed.  Nothing in them
#: may produce a VLEN stack-frame marker, whatever vector loop or ``vlenb``
#: spill they contain.
FIXED_FRAME_FUNCTIONS = (
    "_ZL17add_linker_optionPKci",
    "_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi",
    "_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info",
    "elf_open_debugfile_by_buildid",
)

ALL_FUNCTIONS = (
    CLOSE_AT_FILE,
    "_ZL17add_linker_optionPKci",
    "_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi",
    "_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info",
    "elf_open_debugfile_by_buildid",
)

#: Addresses the gate-2 check reported: the dynamic stack adjustment, the frame
#: restore, the independent error branch that must not inherit the frame state,
#: and the error branches that do follow the adjustment.
DYNAMIC_ADJUSTMENT = 0x21CA6
FRAME_RESTORE = 0x21DD4
INDEPENDENT_ERROR_CALL = 0x21E34  # jal <fatal_error>, on the branch before it
ADJUSTED_ERROR_CALLS = (0x21E4A, 0x21E60, 0x21E76)
#: Internal call sites that were reported as inherited-closure seeds.
SEED_CALL_SITES = (0x21D06, 0x21D14, 0x21D26, 0x21D96, 0x21DC0, 0x21DD0)
#: The instruction that proves ``sp`` is back at the entry base again.
FRAME_RELEASE = FRAME_RESTORE

#: The ``concat`` target the real call sites jump to.
STUB_CALLEE_ADDRESS = 0x9F000
STUB_CALLEE = "_fixture_concat_stub"

STACK_FUNCTIONS_DUMP = r"""\
0000000000021c5e <_ZL13close_at_filev>:
_ZL13close_at_filev():
   21c5e:	711d                	addi	sp,sp,-96
   21c60:	ec86                	sd	ra,88(sp)
   21c62:	e8a2                	sd	s0,80(sp)
   21c64:	e4a6                	sd	s1,72(sp)
   21c66:	e0ca                	sd	s2,64(sp)
   21c68:	fc4e                	sd	s3,56(sp)
   21c6a:	f852                	sd	s4,48(sp)
   21c6c:	f456                	sd	s5,40(sp)
   21c6e:	f05a                	sd	s6,32(sp)
   21c70:	1080                	addi	s0,sp,96
   21c72:	001a4ab7          	lui	s5,0x1a4
   21c76:	050a8a93          	addi	s5,s5,80 # 1a4050 <_ZL16at_file_supplied>
   21c7a:	029ac503          	lbu	a0,41(s5)
   21c7e:	1a050363          	beqz	a0,21e24 <_ZL13close_at_filev+0x1c6>
   21c82:	238ab503          	ld	a0,568(s5)
   21c86:	020a84a3          	sb	zero,41(s5)
   21c8a:	14050563          	beqz	a0,21dd4 <_ZL13close_at_filev+0x176>
_ZNK3vecIPKc7va_heap8vl_embedE6lengthEv():
   21c8e:	00456b03          	lwu	s6,4(a0)
_ZL13close_at_filev():
   21c92:	140b0163          	beqz	s6,21dd4 <_ZL13close_at_filev+0x176>
   21c96:	001b0513          	addi	a0,s6,1
   21c9a:	1502                	slli	a0,a0,0x20
   21c9c:	8175                	srli	a0,a0,0x1d
   21c9e:	053d                	addi	a0,a0,15
   21ca0:	9941                	andi	a0,a0,-16
   21ca2:	40a10a33          	sub	s4,sp,a0
   21ca6:	8152                	mv	sp,s4
_ZL12make_at_filev():
   21ca8:	05caa503          	lw	a0,92(s5)
   21cac:	c125                	beqz	a0,21d0c <_ZL13close_at_filev+0xae>
   21cae:	1e8ab483          	ld	s1,488(s5)
   21cb2:	c481                	beqz	s1,21cba <_ZL13close_at_filev+0x5c>
   21cb4:	0004c503          	lbu	a0,0(s1)
   21cb8:	e919                	bnez	a0,21cce <_ZL13close_at_filev+0x70>
   21cba:	1c0ab483          	ld	s1,448(s5)
   21cbe:	c481                	beqz	s1,21cc6 <_ZL13close_at_filev+0x68>
   21cc0:	0004c503          	lbu	a0,0(s1)
   21cc4:	e509                	bnez	a0,21cce <_ZL13close_at_filev+0x70>
   21cc6:	000e44b7          	lui	s1,0xe4
   21cca:	96948493          	addi	s1,s1,-1687 # e3969 <_ZZ13trim_filenamePKcE9this_file+0x44f>
   21cce:	090aa603          	lw	a2,144(s5)
   21cd2:	00160513          	addi	a0,a2,1
   21cd6:	08aaa823          	sw	a0,144(s5)
   21cda:	000a65b7          	lui	a1,0xa6
   21cde:	10a58593          	addi	a1,a1,266 # a610a <_ZZL9init_specvE2tf+0xb76>
   21ce2:	fa840513          	addi	a0,s0,-88
   21ce6:	fa840913          	addi	s2,s0,-88
   21cea:	b27f20ef          	jal	14810 <sprintf@plt>
   21cee:	1c0ab503          	ld	a0,448(s5)
   21cf2:	012ac583          	lbu	a1,18(s5)
   21cf6:	8d25                	xor	a0,a0,s1
   21cf8:	00153513          	seqz	a0,a0
   21cfc:	8d6d                	and	a0,a0,a1
   21cfe:	00a905b3          	add	a1,s2,a0
   21d02:	8526                	mv	a0,s1
   21d04:	4601                	li	a2,0
   21d06:	2fa7d0ef          	jal	9f000 <concat>
   21d0a:	a039                	j	21d18 <_ZL13close_at_filev+0xba>
   21d0c:	000e5537          	lui	a0,0xe5
   21d10:	f5e50513          	addi	a0,a0,-162 # e4f5e <_ZZ13trim_filenamePKcE9this_file+0x1a44>
   21d14:	6a57e0ef          	jal	a0bb8 <make_temp_file>
   21d18:	892a                	mv	s2,a0
_ZL13close_at_filev():
   21d1a:	000e5537          	lui	a0,0xe5
   21d1e:	8c750513          	addi	a0,a0,-1849 # e48c7 <_ZZ13trim_filenamePKcE9this_file+0x13ad>
   21d22:	85ca                	mv	a1,s2
   21d24:	4601                	li	a2,0
   21d26:	2da7d0ef          	jal	9f000 <concat>
   21d2a:	89aa                	mv	s3,a0
   21d2c:	000ba5b7          	lui	a1,0xba
   21d30:	a4558593          	addi	a1,a1,-1467 # b9a45 <_ZZL9init_specvE2tf+0x144b1>
   21d34:	854a                	mv	a0,s2
   21d36:	97af20ef          	jal	13eb0 <fopen@plt>
   21d3a:	84aa                	mv	s1,a0
   21d3c:	c22026f3          	csrr	a3,vlenb
   21d40:	0026d793          	srli	a5,a3,0x2
   21d44:	4541                	li	a0,16
   21d46:	85be                	mv	a1,a5
   21d48:	00f56363          	bltu	a0,a5,21d4e <_ZL13close_at_filev+0xf0>
   21d4c:	45c1                	li	a1,16
   21d4e:	238ab503          	ld	a0,568(s5)
   21d52:	003b1813          	slli	a6,s6,0x3
   21d56:	00bb6963          	bltu	s6,a1,21d68 <_ZL13close_at_filev+0x10a>
   21d5a:	00169713          	slli	a4,a3,0x1
   21d5e:	40aa05b3          	sub	a1,s4,a0
   21d62:	15e1                	addi	a1,a1,-8
   21d64:	08e5f463          	bgeu	a1,a4,21dec <_ZL13close_at_filev+0x18e>
   21d68:	4601                	li	a2,0
   21d6a:	060e                	slli	a2,a2,0x3
   21d6c:	00a80733          	add	a4,a6,a0
   21d70:	00a606b3          	add	a3,a2,a0
   21d74:	9652                	add	a2,a2,s4
   21d76:	06a1                	addi	a3,a3,8
   21d78:	0721                	addi	a4,a4,8
   21d7a:	628c                	ld	a1,0(a3)
   21d7c:	06a1                	addi	a3,a3,8
   21d7e:	e20c                	sd	a1,0(a2)
   21d80:	0621                	addi	a2,a2,8
   21d82:	fee69ce3          	bne	a3,a4,21d7a <_ZL13close_at_filev+0x11c>
   21d86:	9852                	add	a6,a6,s4
   21d88:	00083023          	sd	zero,0(a6)
_ZN3vecIPKc7va_heap8vl_embedE8truncateEj():
   21d8c:	00052223          	sw	zero,4(a0)
_ZL13close_at_filev():
   21d90:	c4c5                	beqz	s1,21e38 <_ZL13close_at_filev+0x1da>
   21d92:	8552                	mv	a0,s4
   21d94:	85a6                	mv	a1,s1
   21d96:	6597c0ef          	jal	9ebee <writeargv>
   21d9a:	e955                	bnez	a0,21e4e <_ZL13close_at_filev+0x1f0>
   21d9c:	8526                	mv	a0,s1
   21d9e:	8f2f20ef          	jal	13e90 <fclose@plt>
   21da2:	55fd                	li	a1,-1
   21da4:	0cb50063          	beq	a0,a1,21e64 <_ZL13close_at_filev+0x206>
_ZL9store_argPKcii():
   21da8:	029ac503          	lbu	a0,41(s5)
   21dac:	fb343423          	sd	s3,-88(s0)
   21db0:	e501                	bnez	a0,21db8 <_ZL13close_at_filev+0x15a>
   21db2:	0c8a8513          	addi	a0,s5,200
   21db6:	a019                	j	21dbc <_ZL13close_at_filev+0x15e>
   21db8:	238a8513          	addi	a0,s5,568
   21dbc:	fa840593          	addi	a1,s0,-88
   21dc0:	62e020ef          	jal	243ee <_ZN3vecIPKc7va_heap6vl_ptrE9safe_pushERKS1_>
_ZL13close_at_filev():
   21dc4:	05caa503          	lw	a0,92(s5)
   21dc8:	00153593          	seqz	a1,a0
   21dcc:	854a                	mv	a0,s2
   21dce:	862e                	mv	a2,a1
   21dd0:	de0f30ef          	jal	153b0 <_Z16record_temp_filePKcii>
   21dd4:	fa040113          	addi	sp,s0,-96
   21dd8:	60e6                	ld	ra,88(sp)
   21dda:	6446                	ld	s0,80(sp)
   21ddc:	64a6                	ld	s1,72(sp)
   21dde:	6906                	ld	s2,64(sp)
   21de0:	79e2                	ld	s3,56(sp)
   21de2:	7a42                	ld	s4,48(sp)
   21de4:	7aa2                	ld	s5,40(sp)
   21de6:	7b02                	ld	s6,32(sp)
   21de8:	6125                	addi	sp,sp,96
   21dea:	8082                	ret
   21dec:	40f005b3          	neg	a1,a5
   21df0:	0165f633          	and	a2,a1,s6
   21df4:	40f605b3          	sub	a1,a2,a5
   21df8:	02f5d5b3          	divu	a1,a1,a5
   21dfc:	00850793          	addi	a5,a0,8
   21e00:	828d                	srli	a3,a3,0x3
   21e02:	0592                	slli	a1,a1,0x4
   21e04:	05c1                	addi	a1,a1,16
   21e06:	02d585b3          	mul	a1,a1,a3
   21e0a:	95d2                	add	a1,a1,s4
   21e0c:	86d2                	mv	a3,s4
   21e0e:	2287f407          	vl2re64.v	v8,(a5)
   21e12:	22868427          	vs2r.v	v8,(a3)
   21e16:	96ba                	add	a3,a3,a4
   21e18:	97ba                	add	a5,a5,a4
   21e1a:	feb69ae3          	bne	a3,a1,21e0e <_ZL13close_at_filev+0x1b0>
   21e1e:	f76604e3          	beq	a2,s6,21d86 <_ZL13close_at_filev+0x128>
   21e22:	b7a1                	j	21d6a <_ZL13close_at_filev+0x10c>
   21e24:	001a8537          	lui	a0,0x1a8
   21e28:	9e053503          	ld	a0,-1568(a0) # 1a79e0 <input_location>
   21e2c:	000a65b7          	lui	a1,0xa6
   21e30:	06058593          	addi	a1,a1,96 # a6060 <_ZZL9init_specvE2tf+0xacc>
   21e34:	1222c0ef          	jal	4df56 <_Z11fatal_errormPKcz>
   21e38:	001a8537          	lui	a0,0x1a8
   21e3c:	9e053503          	ld	a0,-1568(a0) # 1a79e0 <input_location>
   21e40:	000a65b7          	lui	a1,0xa6
   21e44:	08758593          	addi	a1,a1,135 # a6087 <_ZZL9init_specvE2tf+0xaf3>
   21e48:	864a                	mv	a2,s2
   21e4a:	10c2c0ef          	jal	4df56 <_Z11fatal_errormPKcz>
   21e4e:	001a8537          	lui	a0,0x1a8
   21e52:	9e053503          	ld	a0,-1568(a0) # 1a79e0 <input_location>
   21e56:	000a65b7          	lui	a1,0xa6
   21e5a:	0b158593          	addi	a1,a1,177 # a60b1 <_ZZL9init_specvE2tf+0xb1d>
   21e5e:	864a                	mv	a2,s2
   21e60:	0f62c0ef          	jal	4df56 <_Z11fatal_errormPKcz>
   21e64:	001a8537          	lui	a0,0x1a8
   21e68:	9e053503          	ld	a0,-1568(a0) # 1a79e0 <input_location>
   21e6c:	000a65b7          	lui	a1,0xa6
   21e70:	0df58593          	addi	a1,a1,223 # a60df <_ZZL9init_specvE2tf+0xb4b>
   21e74:	864a                	mv	a2,s2
   21e76:	0e02c0ef          	jal	4df56 <_Z11fatal_errormPKcz>
0000000000020fee <_ZL17add_linker_optionPKci>:
_ZL17add_linker_optionPKci():
   20fee:	715d                	addi	sp,sp,-80
   20ff0:	e486                	sd	ra,72(sp)
   20ff2:	e0a2                	sd	s0,64(sp)
   20ff4:	fc26                	sd	s1,56(sp)
   20ff6:	f84a                	sd	s2,48(sp)
   20ff8:	f44e                	sd	s3,40(sp)
   20ffa:	f052                	sd	s4,32(sp)
   20ffc:	ec56                	sd	s5,24(sp)
   20ffe:	e85a                	sd	s6,16(sp)
   21000:	e45e                	sd	s7,8(sp)
   21002:	84ae                	mv	s1,a1
   21004:	842a                	mv	s0,a0
   21006:	80000ab7          	lui	s5,0x80000
   2100a:	3afd                	addiw	s5,s5,-1 # 7fffffff <__BSS_END__+0x7fe5829f>
   2100c:	0015851b          	addiw	a0,a1,1
   21010:	2cd800ef          	jal	a1adc <xmalloc>
   21014:	892a                	mv	s2,a0
   21016:	85a2                	mv	a1,s0
   21018:	8626                	mv	a2,s1
   2101a:	c96f30ef          	jal	144b0 <memcpy@plt>
   2101e:	001a49b7          	lui	s3,0x1a4
   21022:	2509b403          	ld	s0,592(s3) # 1a4250 <_ZL14linker_options.0>
   21026:	94ca                	add	s1,s1,s2
   21028:	00048023          	sb	zero,0(s1)
   2102c:	c41d                	beqz	s0,2105a <_ZL17add_linker_optionPKci+0x6c>
_ZNK3vecIPc7va_heap8vl_embedE5spaceEj():
   2102e:	400c                	lw	a1,0(s0)
   21030:	4050                	lw	a2,4(s0)
   21032:	0155f533          	and	a0,a1,s5
_ZL17add_linker_optionPKci():
   21036:	0ac51a63          	bne	a0,a2,210ea <_ZL17add_linker_optionPKci+0xfc>
   2103a:	0c05cc63          	bltz	a1,21112 <_ZL17add_linker_optionPKci+0x124>
   2103e:	0015059b          	addiw	a1,a0,1
   21042:	6711a0ef          	jal	3beb2 <_ZN10vec_prefix22calculate_allocation_1Ejj>
   21046:	2509b583          	ld	a1,592(s3)
   2104a:	84aa                	mv	s1,a0
   2104c:	cde9                	beqz	a1,21126 <_ZL17add_linker_optionPKci+0x138>
   2104e:	852e                	mv	a0,a1
   21050:	4a01                	li	s4,0
_ZNK3vecIPc7va_heap8vl_embedE6lengthEv():
   21052:	0045ab03          	lw	s6,4(a1)
   21056:	4b81                	li	s7,0
   21058:	a819                	j	2106e <_ZL17add_linker_optionPKci+0x80>
_ZL17add_linker_optionPKci():
   2105a:	4a01                	li	s4,0
   2105c:	4485                	li	s1,1
   2105e:	4511                	li	a0,4
   21060:	00956363          	bltu	a0,s1,21066 <_ZL17add_linker_optionPKci+0x78>
   21064:	4491                	li	s1,4
   21066:	4501                	li	a0,0
   21068:	4b01                	li	s6,0
   2106a:	00803bb3          	snez	s7,s0
_ZN3vecIPc7va_heap8vl_embedE13embedded_sizeEj():
   2106e:	02049593          	slli	a1,s1,0x20
   21072:	81f5                	srli	a1,a1,0x1d
   21074:	05a1                	addi	a1,a1,8
_ZL17add_linker_optionPKci():
   21076:	2c1800ef          	jal	a1b36 <xrealloc>
   2107a:	24a9b823          	sd	a0,592(s3)
_ZN3vecIPc7va_heap8vl_embedE13embedded_initEjjj():
   2107e:	0154f5b3          	and	a1,s1,s5
   21082:	c10c                	sw	a1,0(a0)
   21084:	01652223          	sw	s6,4(a0)
_ZL17add_linker_optionPKci():
   21088:	060b8063          	beqz	s7,210e8 <_ZL17add_linker_optionPKci+0xfa>
   2108c:	040a0963          	beqz	s4,210de <_ZL17add_linker_optionPKci+0xf0>
   21090:	020a1593          	slli	a1,s4,0x20
   21094:	c2202773          	csrr	a4,vlenb
   21098:	00275613          	srli	a2,a4,0x2
   2109c:	47c1                	li	a5,16
   2109e:	9181                	srli	a1,a1,0x20
   210a0:	86b2                	mv	a3,a2
   210a2:	00c7e363          	bltu	a5,a2,210a8 <_ZL17add_linker_optionPKci+0xba>
   210a6:	46c1                	li	a3,16
   210a8:	00d5e863          	bltu	a1,a3,210b8 <_ZL17add_linker_optionPKci+0xca>
   210ac:	00171693          	slli	a3,a4,0x1
   210b0:	408507b3          	sub	a5,a0,s0
   210b4:	06d7fe63          	bgeu	a5,a3,21130 <_ZL17add_linker_optionPKci+0x142>
   210b8:	88d2                	mv	a7,s4
   210ba:	8722                	mv	a4,s0
   210bc:	82aa                	mv	t0,a0
   210be:	00870593          	addi	a1,a4,8
   210c2:	02a1                	addi	t0,t0,8
   210c4:	18fd                	addi	a7,a7,-1
   210c6:	1882                	slli	a7,a7,0x20
   210c8:	01d8d613          	srli	a2,a7,0x1d
   210cc:	963a                	add	a2,a2,a4
   210ce:	0641                	addi	a2,a2,16
   210d0:	6194                	ld	a3,0(a1)
   210d2:	05a1                	addi	a1,a1,8
   210d4:	00d2b023          	sd	a3,0(t0)
   210d8:	02a1                	addi	t0,t0,8
   210da:	fec59be3          	bne	a1,a2,210d0 <_ZL17add_linker_optionPKci+0xe2>
   210de:	01452223          	sw	s4,4(a0)
_ZN3vecIPc7va_heap6vl_ptrE10quick_pushERKS0_():
   210e2:	2509b403          	ld	s0,592(s3)
   210e6:	a011                	j	210ea <_ZL17add_linker_optionPKci+0xfc>
   210e8:	842a                	mv	s0,a0
_ZN3vecIPc7va_heap8vl_embedE10quick_pushERKS0_():
   210ea:	00446503          	lwu	a0,4(s0)
   210ee:	00351593          	slli	a1,a0,0x3
   210f2:	0505                	addi	a0,a0,1
_ZN3vecIPc7va_heap8vl_embedE7addressEv():
   210f4:	95a2                	add	a1,a1,s0
_ZN3vecIPc7va_heap8vl_embedE10quick_pushERKS0_():
   210f6:	c048                	sw	a0,4(s0)
   210f8:	0125b423          	sd	s2,8(a1)
_ZL17add_linker_optionPKci():
   210fc:	60a6                	ld	ra,72(sp)
   210fe:	6406                	ld	s0,64(sp)
   21100:	74e2                	ld	s1,56(sp)
   21102:	7942                	ld	s2,48(sp)
   21104:	79a2                	ld	s3,40(sp)
   21106:	7a02                	ld	s4,32(sp)
   21108:	6ae2                	ld	s5,24(sp)
   2110a:	6b42                	ld	s6,16(sp)
   2110c:	6ba2                	ld	s7,8(sp)
   2110e:	6161                	addi	sp,sp,80
   21110:	8082                	ret
   21112:	2409b823          	sd	zero,592(s3)
_ZNK3vecIPc7va_heap8vl_embedE6lengthEv():
   21116:	00442a03          	lw	s4,4(s0)
_ZL17add_linker_optionPKci():
   2111a:	001a049b          	addiw	s1,s4,1
   2111e:	4511                	li	a0,4
   21120:	f49572e3          	bgeu	a0,s1,21064 <_ZL17add_linker_optionPKci+0x76>
   21124:	b789                	j	21066 <_ZL17add_linker_optionPKci+0x78>
   21126:	4a01                	li	s4,0
   21128:	4b81                	li	s7,0
   2112a:	4501                	li	a0,0
   2112c:	4b01                	li	s6,0
   2112e:	b781                	j	2106e <_ZL17add_linker_optionPKci+0x80>
   21130:	8309                	srli	a4,a4,0x2
   21132:	00850793          	addi	a5,a0,8
   21136:	40e00733          	neg	a4,a4
   2113a:	00b77833          	and	a6,a4,a1
   2113e:	410a08bb          	subw	a7,s4,a6
   21142:	00381293          	slli	t0,a6,0x3
   21146:	00540733          	add	a4,s0,t0
   2114a:	92aa                	add	t0,t0,a0
   2114c:	0421                	addi	s0,s0,8
   2114e:	84c2                	mv	s1,a6
   21150:	22847407          	vl2re64.v	v8,(s0)
   21154:	8c91                	sub	s1,s1,a2
   21156:	22878427          	vs2r.v	v8,(a5)
   2115a:	97b6                	add	a5,a5,a3
   2115c:	9436                	add	s0,s0,a3
   2115e:	f8ed                	bnez	s1,21150 <_ZL17add_linker_optionPKci+0x162>
   21160:	f4b81fe3          	bne	a6,a1,210be <_ZL17add_linker_optionPKci+0xd0>
   21164:	bfad                	j	210de <_ZL17add_linker_optionPKci+0xf0>
000000000004f956 <_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi>:
_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi():
   4f956:	715d                	addi	sp,sp,-80
   4f958:	e486                	sd	ra,72(sp)
   4f95a:	e0a2                	sd	s0,64(sp)
   4f95c:	fc26                	sd	s1,56(sp)
   4f95e:	f84a                	sd	s2,48(sp)
   4f960:	f44e                	sd	s3,40(sp)
   4f962:	f052                	sd	s4,32(sp)
   4f964:	ec56                	sd	s5,24(sp)
   4f966:	e85a                	sd	s6,16(sp)
   4f968:	e45e                	sd	s7,8(sp)
   4f96a:	8b2e                	mv	s6,a1
   4f96c:	8baa                	mv	s7,a0
   4f96e:	15053403          	ld	s0,336(a0)
   4f972:	15853503          	ld	a0,344(a0)
   4f976:	00141593          	slli	a1,s0,0x1
   4f97a:	95a2                	add	a1,a1,s0
   4f97c:	00251613          	slli	a2,a0,0x2
   4f980:	0012dab7          	lui	s5,0x12d
   4f984:	ba0a8a93          	addi	s5,s5,-1120 # 12cba0 <prime_tab>
   4f988:	1eb66163          	bltu	a2,a1,4fb6a <_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi+0x214>
   4f98c:	160bb583          	ld	a1,352(s7)
   4f990:	148bb903          	ld	s2,328(s7)
   4f994:	40b505b3          	sub	a1,a0,a1
   4f998:	00159513          	slli	a0,a1,0x1
   4f99c:	00a46d63          	bltu	s0,a0,4f9b6 <_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi+0x60>
   4f9a0:	170baa03          	lw	s4,368(s7)
   4f9a4:	02100613          	li	a2,33
   4f9a8:	04c46063          	bltu	s0,a2,4f9e8 <_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi+0x92>
   4f9ac:	158e                	slli	a1,a1,0x23
   4f9ae:	9181                	srli	a1,a1,0x20
   4f9b0:	89a2                	mv	s3,s0
   4f9b2:	0085fa63          	bgeu	a1,s0,4f9c6 <_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi+0x70>
   4f9b6:	9a7ed0ef          	jal	3d35c <_Z29hash_table_higher_prime_indexm>
   4f9ba:	8a2a                	mv	s4,a0
   4f9bc:	1502                	slli	a0,a0,0x20
   4f9be:	8171                	srli	a0,a0,0x1c
   4f9c0:	9556                	add	a0,a0,s5
   4f9c2:	00056983          	lwu	s3,0(a0)
   4f9c6:	174bc503          	lbu	a0,372(s7)
   4f9ca:	c11d                	beqz	a0,4f9f0 <_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi+0x9a>
_Z21ggc_cleared_vec_allocIN8hash_mapI8int_hashIiLin1ELin2EEN12_GLOBAL__N_111event_range20per_source_line_infoE21simple_hashmap_traitsI19default_hash_traitsIS2_ES5_EE10hash_entryEEPT_m():
   4f9cc:	00299513          	slli	a0,s3,0x2
   4f9d0:	00499593          	slli	a1,s3,0x4
   4f9d4:	952e                	add	a0,a0,a1
   4f9d6:	000505b7          	lui	a1,0x50
   4f9da:	cde58593          	addi	a1,a1,-802 # 4fcde <_Z8finalizeIN8hash_mapI8int_hashIiLin1ELin2EEN12_GLOBAL__N_111event_range20per_source_line_infoE21simple_hashmap_traitsI19default_hash_traitsIS2_ES5_EE10hash_entryEEvPv>
   4f9de:	4651                	li	a2,20
   4f9e0:	86ce                	mv	a3,s3
   4f9e2:	b67d40ef          	jal	24548 <_Z26ggc_internal_cleared_allocmPFvPvEmm>
   4f9e6:	a809                	j	4f9f8 <_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi+0xa2>
_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi():
   4f9e8:	89a2                	mv	s3,s0
   4f9ea:	174bc503          	lbu	a0,372(s7)
   4f9ee:	fd79                	bnez	a0,4f9cc <_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi+0x76>
_ZN11xcallocatorIN8hash_mapI8int_hashIiLin1ELin2EEN12_GLOBAL__N_111event_range20per_source_line_infoE21simple_hashmap_traitsI19default_hash_traitsIS2_ES5_EE10hash_entryEE10data_allocEm():
   4f9f0:	45d1                	li	a1,20
   4f9f2:	854e                	mv	a0,s3
   4f9f4:	10a520ef          	jal	a1afe <xcalloc>
_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi():
   4f9f8:	2c050763          	beqz	a0,4fcc6 <_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi+0x370>
   4f9fc:	00241593          	slli	a1,s0,0x2
   4fa00:	0412                	slli	s0,s0,0x4
   4fa02:	95a2                	add	a1,a1,s0
   4fa04:	06098163          	beqz	s3,4fa66 <_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi+0x110>
   4fa08:	c22026f3          	csrr	a3,vlenb
   4fa0c:	0016d613          	srli	a2,a3,0x1
   4fa10:	00c9f463          	bgeu	s3,a2,4fa18 <_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi+0xc2>
   4fa14:	4401                	li	s0,0
   4fa16:	a805                	j	4fa46 <_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi+0xf0>
   4fa18:	828d                	srli	a3,a3,0x3
   4fa1a:	40c00733          	neg	a4,a2
   4fa1e:	0d1077d7          	vsetvli	a5,zero,e32,m2,ta,ma
   4fa22:	5e0fb457          	vmv.v.i	v8,-1
   4fa26:	00e9f433          	and	s0,s3,a4
   4fa2a:	00469493          	slli	s1,a3,0x4
   4fa2e:	069a                	slli	a3,a3,0x6
   4fa30:	94b6                	add	s1,s1,a3
   4fa32:	47d1                	li	a5,20
   4fa34:	872a                	mv	a4,a0
   4fa36:	86a2                	mv	a3,s0
   4fa38:	0af76427          	vsse32.v	v8,(a4),a5
   4fa3c:	8e91                	sub	a3,a3,a2
   4fa3e:	9726                	add	a4,a4,s1
   4fa40:	fee5                	bnez	a3,4fa38 <_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi+0xe2>
   4fa42:	02898263          	beq	s3,s0,4fa66 <_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi+0x110>
   4fa46:	00241613          	slli	a2,s0,0x2
   4fa4a:	0412                	slli	s0,s0,0x4
   4fa4c:	00299693          	slli	a3,s3,0x2
   4fa50:	9622                	add	a2,a2,s0
   4fa52:	00499713          	slli	a4,s3,0x4
   4fa56:	96ba                	add	a3,a3,a4
   4fa58:	962a                	add	a2,a2,a0
   4fa5a:	96aa                	add	a3,a3,a0
   4fa5c:	577d                	li	a4,-1
   4fa5e:	c218                	sw	a4,0(a2)
   4fa60:	0651                	addi	a2,a2,20
   4fa62:	fed61ee3          	bne	a2,a3,4fa5e <_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi+0x108>
   4fa66:	158bb603          	ld	a2,344(s7)
   4fa6a:	160bb683          	ld	a3,352(s7)
   4fa6e:	00b908b3          	add	a7,s2,a1
   4fa72:	174ba823          	sw	s4,368(s7)
   4fa76:	4585                	li	a1,1
   4fa78:	40d606b3          	sub	a3,a2,a3
   4fa7c:	5e7d                	li	t3,-1
   4fa7e:	1582                	slli	a1,a1,0x20
   4fa80:	ffd58293          	addi	t0,a1,-3
   4fa84:	14abb423          	sd	a0,328(s7)
   4fa88:	153bb823          	sd	s3,336(s7)
   4fa8c:	14dbbc23          	sd	a3,344(s7)
   4fa90:	160bb023          	sd	zero,352(s7)
   4fa94:	4809                	li	a6,2
   4fa96:	874a                	mv	a4,s2
   4fa98:	a821                	j	4fab0 <_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi+0x15a>
   4fa9a:	4b08                	lw	a0,16(a4)
   4fa9c:	cb88                	sw	a0,16(a5)
   4fa9e:	cd027057          	vsetivli	zero,4,e32,m1,ta,ma
   4faa2:	02076407          	vle32.v	v8,(a4)
   4faa6:	0207e427          	vse32.v	v8,(a5)
   4faaa:	0751                	addi	a4,a4,20
   4faac:	0b177563          	bgeu	a4,a7,4fb56 <_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi+0x200>
_ZN21simple_hashmap_traitsI19default_hash_traitsI8int_hashIiLin1ELin2EEEN12_GLOBAL__N_111event_range20per_source_line_infoEE8is_emptyIN8hash_mapIS2_S6_S7_E10hash_entryEEEbRKT_():
   4fab0:	00076603          	lwu	a2,0(a4)
_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi():
   4fab4:	fec2ebe3          	bltu	t0,a2,4faaa <_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi+0x154>
_ZN10hash_tableIN8hash_mapI8int_hashIiLin1ELin2EEN12_GLOBAL__N_111event_range20per_source_line_infoE21simple_hashmap_traitsI19default_hash_traitsIS2_ES5_EE10hash_entryELb0E11xcallocatorE26find_empty_slot_for_expandEj():
   4fab8:	170be503          	lwu	a0,368(s7)
   4fabc:	0512                	slli	a0,a0,0x4
   4fabe:	00aa84b3          	add	s1,s5,a0
   4fac2:	0044e503          	lwu	a0,4(s1)
   4fac6:	148bb683          	ld	a3,328(s7)
   4faca:	0004a383          	lw	t2,0(s1)
   4face:	00c4e303          	lwu	t1,12(s1)
_Z7mul_modjjji():
   4fad2:	02c50533          	mul	a0,a0,a2
   4fad6:	9101                	srli	a0,a0,0x20
   4fad8:	40a607bb          	subw	a5,a2,a0
   4fadc:	0017d79b          	srliw	a5,a5,0x1
   4fae0:	953e                	add	a0,a0,a5
   4fae2:	0065553b          	srlw	a0,a0,t1
   4fae6:	02750533          	mul	a0,a0,t2
   4faea:	40a6053b          	subw	a0,a2,a0
_ZN10hash_tableIN8hash_mapI8int_hashIiLin1ELin2EEN12_GLOBAL__N_111event_range20per_source_line_infoE21simple_hashmap_traitsI19default_hash_traitsIS2_ES5_EE10hash_entryELb0E11xcallocatorE26find_empty_slot_for_expandEj():
   4faee:	02051793          	slli	a5,a0,0x20
   4faf2:	01e7d593          	srli	a1,a5,0x1e
   4faf6:	83f1                	srli	a5,a5,0x1c
   4faf8:	95be                	add	a1,a1,a5
   4fafa:	00b687b3          	add	a5,a3,a1
_ZN21simple_hashmap_traitsI19default_hash_traitsI8int_hashIiLin1ELin2EEEN12_GLOBAL__N_111event_range20per_source_line_infoEE8is_emptyIN8hash_mapIS2_S6_S7_E10hash_entryEEEbRKT_():
   4fafe:	438c                	lw	a1,0(a5)
_ZN10hash_tableIN8hash_mapI8int_hashIiLin1ELin2EEN12_GLOBAL__N_111event_range20per_source_line_infoE21simple_hashmap_traitsI19default_hash_traitsIS2_ES5_EE10hash_entryELb0E11xcallocatorE26find_empty_slot_for_expandEj():
   4fb00:	f9c58de3          	beq	a1,t3,4fa9a <_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi+0x144>
   4fb04:	0084e583          	lwu	a1,8(s1)
   4fb08:	150bb483          	ld	s1,336(s7)
   4fb0c:	407807bb          	subw	a5,a6,t2
_Z7mul_modjjji():
   4fb10:	02c585b3          	mul	a1,a1,a2
   4fb14:	9181                	srli	a1,a1,0x20
   4fb16:	40b6043b          	subw	s0,a2,a1
   4fb1a:	0014541b          	srliw	s0,s0,0x1
   4fb1e:	95a2                	add	a1,a1,s0
   4fb20:	0065d5bb          	srlw	a1,a1,t1
   4fb24:	02f585b3          	mul	a1,a1,a5
   4fb28:	95b2                	add	a1,a1,a2
_ZN10hash_tableIN8hash_mapI8int_hashIiLin1ELin2EEN12_GLOBAL__N_111event_range20per_source_line_infoE21simple_hashmap_traitsI19default_hash_traitsIS2_ES5_EE10hash_entryELb0E11xcallocatorE26find_empty_slot_for_expandEj():
   4fb2a:	0585                	addi	a1,a1,1
   4fb2c:	952e                	add	a0,a0,a1
   4fb2e:	02051613          	slli	a2,a0,0x20
   4fb32:	9201                	srli	a2,a2,0x20
   4fb34:	00963633          	sltu	a2,a2,s1
   4fb38:	167d                	addi	a2,a2,-1
   4fb3a:	8e65                	and	a2,a2,s1
   4fb3c:	9d11                	subw	a0,a0,a2
   4fb3e:	02051613          	slli	a2,a0,0x20
   4fb42:	01e65793          	srli	a5,a2,0x1e
   4fb46:	8271                	srli	a2,a2,0x1c
   4fb48:	963e                	add	a2,a2,a5
   4fb4a:	00c687b3          	add	a5,a3,a2
_ZN21simple_hashmap_traitsI19default_hash_traitsI8int_hashIiLin1ELin2EEEN12_GLOBAL__N_111event_range20per_source_line_infoEE8is_emptyIN8hash_mapIS2_S6_S7_E10hash_entryEEEbRKT_():
   4fb4e:	4390                	lw	a2,0(a5)
_ZN10hash_tableIN8hash_mapI8int_hashIiLin1ELin2EEN12_GLOBAL__N_111event_range20per_source_line_infoE21simple_hashmap_traitsI19default_hash_traitsIS2_ES5_EE10hash_entryELb0E11xcallocatorE26find_empty_slot_for_expandEj():
   4fb50:	fdc61ee3          	bne	a2,t3,4fb2c <_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi+0x1d6>
   4fb54:	b799                	j	4fa9a <_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi+0x144>
_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi():
   4fb56:	174bc503          	lbu	a0,372(s7)
   4fb5a:	c509                	beqz	a0,4fb64 <_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi+0x20e>
   4fb5c:	854a                	mv	a0,s2
   4fb5e:	a13d40ef          	jal	24570 <_Z8ggc_freePv>
   4fb62:	a021                	j	4fb6a <_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi+0x214>
_ZN11xcallocatorIN8hash_mapI8int_hashIiLin1ELin2EEN12_GLOBAL__N_111event_range20per_source_line_infoE21simple_hashmap_traitsI19default_hash_traitsIS2_ES5_EE10hash_entryEE9data_freeEPSB_():
   4fb64:	854a                	mv	a0,s2
   4fb66:	8fbc40ef          	jal	14460 <free@plt>
_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi():
   4fb6a:	148bb383          	ld	t2,328(s7)
   4fb6e:	150bb583          	ld	a1,336(s7)
   4fb72:	168ba603          	lw	a2,360(s7)
   4fb76:	170be683          	lwu	a3,368(s7)
   4fb7a:	020b1413          	slli	s0,s6,0x20
   4fb7e:	9001                	srli	s0,s0,0x20
   4fb80:	0605                	addi	a2,a2,1
   4fb82:	0692                	slli	a3,a3,0x4
   4fb84:	16cba423          	sw	a2,360(s7)
   4fb88:	96d6                	add	a3,a3,s5
   4fb8a:	0046e703          	lwu	a4,4(a3)
   4fb8e:	0006a303          	lw	t1,0(a3)
_Z15hash_table_mod2jj():
   4fb92:	0086e883          	lwu	a7,8(a3)
_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi():
   4fb96:	00c6e283          	lwu	t0,12(a3)
   4fb9a:	028706b3          	mul	a3,a4,s0
   4fb9e:	9281                	srli	a3,a3,0x20
   4fba0:	40db073b          	subw	a4,s6,a3
   4fba4:	0017571b          	srliw	a4,a4,0x1
   4fba8:	96ba                	add	a3,a3,a4
   4fbaa:	0056d6bb          	srlw	a3,a3,t0
   4fbae:	026686b3          	mul	a3,a3,t1
   4fbb2:	40db07bb          	subw	a5,s6,a3
   4fbb6:	02079493          	slli	s1,a5,0x20
   4fbba:	01e4d693          	srli	a3,s1,0x1e
   4fbbe:	01c4d713          	srli	a4,s1,0x1c
   4fbc2:	96ba                	add	a3,a3,a4
   4fbc4:	00d38533          	add	a0,t2,a3
_ZN21simple_hashmap_traitsI19default_hash_traitsI8int_hashIiLin1ELin2EEEN12_GLOBAL__N_111event_range20per_source_line_infoEE8is_emptyIN8hash_mapIS2_S6_S7_E10hash_entryEEEbRKT_():
   4fbc8:	4114                	lw	a3,0(a0)
   4fbca:	5879                	li	a6,-2
_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi():
   4fbcc:	01068a63          	beq	a3,a6,4fbe0 <_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi+0x28a>
   4fbd0:	567d                	li	a2,-1
   4fbd2:	00c69463          	bne	a3,a2,4fbda <_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi+0x284>
   4fbd6:	9081                	srli	s1,s1,0x20
   4fbd8:	a841                	j	4fc68 <_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi+0x312>
   4fbda:	0b668763          	beq	a3,s6,4fc88 <_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi+0x332>
   4fbde:	4501                	li	a0,0
   4fbe0:	4609                	li	a2,2
   4fbe2:	028886b3          	mul	a3,a7,s0
   4fbe6:	16cba403          	lw	s0,364(s7)
   4fbea:	4066063b          	subw	a2,a2,t1
   4fbee:	9281                	srli	a3,a3,0x20
   4fbf0:	40db04bb          	subw	s1,s6,a3
   4fbf4:	0014d49b          	srliw	s1,s1,0x1
   4fbf8:	96a6                	add	a3,a3,s1
   4fbfa:	0056d6bb          	srlw	a3,a3,t0
   4fbfe:	02c68633          	mul	a2,a3,a2
   4fc02:	965a                	add	a2,a2,s6
   4fc04:	00160693          	addi	a3,a2,1
   4fc08:	52fd                	li	t0,-1
   4fc0a:	88aa                	mv	a7,a0
   4fc0c:	0405                	addi	s0,s0,1
   4fc0e:	168ba623          	sw	s0,364(s7)
   4fc12:	97b6                	add	a5,a5,a3
   4fc14:	02079613          	slli	a2,a5,0x20
   4fc18:	9201                	srli	a2,a2,0x20
   4fc1a:	00b63633          	sltu	a2,a2,a1
   4fc1e:	167d                	addi	a2,a2,-1
   4fc20:	8e6d                	and	a2,a2,a1
   4fc22:	9f91                	subw	a5,a5,a2
   4fc24:	02079713          	slli	a4,a5,0x20
   4fc28:	01e75513          	srli	a0,a4,0x1e
   4fc2c:	01c75613          	srli	a2,a4,0x1c
   4fc30:	9532                	add	a0,a0,a2
   4fc32:	951e                	add	a0,a0,t2
_ZN21simple_hashmap_traitsI19default_hash_traitsI8int_hashIiLin1ELin2EEEN12_GLOBAL__N_111event_range20per_source_line_infoEE8is_emptyIN8hash_mapIS2_S6_S7_E10hash_entryEEEbRKT_():
   4fc34:	4104                	lw	s1,0(a0)
_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi():
   4fc36:	00548c63          	beq	s1,t0,4fc4e <_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi+0x2f8>
   4fc3a:	01048663          	beq	s1,a6,4fc46 <_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi+0x2f0>
   4fc3e:	0405                	addi	s0,s0,1
   4fc40:	fd6497e3          	bne	s1,s6,4fc0e <_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi+0x2b8>
   4fc44:	a091                	j	4fc88 <_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi+0x332>
   4fc46:	fc0882e3          	beqz	a7,4fc0a <_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi+0x2b4>
   4fc4a:	8546                	mv	a0,a7
   4fc4c:	bf7d                	j	4fc0a <_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi+0x2b4>
   4fc4e:	00088b63          	beqz	a7,4fc64 <_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi+0x30e>
   4fc52:	160bb503          	ld	a0,352(s7)
   4fc56:	157d                	addi	a0,a0,-1
   4fc58:	16abb023          	sd	a0,352(s7)
   4fc5c:	557d                	li	a0,-1
_ZN8int_hashIiLin1ELin2EE10mark_emptyERi():
   4fc5e:	00a8a023          	sw	a0,0(a7)
   4fc62:	a02d                	j	4fc8c <_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi+0x336>
_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi():
   4fc64:	02075493          	srli	s1,a4,0x20
   4fc68:	158bb503          	ld	a0,344(s7)
   4fc6c:	00249593          	slli	a1,s1,0x2
   4fc70:	0492                	slli	s1,s1,0x4
   4fc72:	95a6                	add	a1,a1,s1
   4fc74:	0505                	addi	a0,a0,1
   4fc76:	14abbc23          	sd	a0,344(s7)
   4fc7a:	00b38533          	add	a0,t2,a1
_ZN21simple_hashmap_traitsI19default_hash_traitsI8int_hashIiLin1ELin2EEEN12_GLOBAL__N_111event_range20per_source_line_infoEE8is_emptyIN8hash_mapIS2_S6_S7_E10hash_entryEEEbRKT_():
   4fc7e:	410c                	lw	a1,0(a0)
   4fc80:	567d                	li	a2,-1
   4fc82:	88aa                	mv	a7,a0
_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi():
   4fc84:	00c58463          	beq	a1,a2,4fc8c <_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi+0x336>
   4fc88:	0511                	addi	a0,a0,4
   4fc8a:	a01d                	j	4fcb0 <_ZN12_GLOBAL__N_111event_range24get_per_source_line_infoEi+0x35a>
   4fc8c:	00488513          	addi	a0,a7,4
   4fc90:	800005b7          	lui	a1,0x80000
   4fc94:	fff58613          	addi	a2,a1,-1 # ffffffff7fffffff <__BSS_END__+0xffffffff7fe5829f>
   4fc98:	0168a023          	sw	s6,0(a7)
   4fc9c:	0168a223          	sw	s6,4(a7)
   4fca0:	0008a423          	sw	zero,8(a7)
   4fca4:	00c8a623          	sw	a2,12(a7)
   4fca8:	000884a3          	sb	zero,9(a7)
   4fcac:	00b8a823          	sw	a1,16(a7)
   4fcb0:	60a6                	ld	ra,72(sp)
   4fcb2:	6406                	ld	s0,64(sp)
   4fcb4:	74e2                	ld	s1,56(sp)
   4fcb6:	7942                	ld	s2,48(sp)
   4fcb8:	79a2                	ld	s3,40(sp)
   4fcba:	7a02                	ld	s4,32(sp)
   4fcbc:	6ae2                	ld	s5,24(sp)
   4fcbe:	6b42                	ld	s6,16(sp)
   4fcc0:	6ba2                	ld	s7,8(sp)
   4fcc2:	6161                	addi	sp,sp,80
   4fcc4:	8082                	ret
   4fcc6:	000e3537          	lui	a0,0xe3
   4fcca:	e0150513          	addi	a0,a0,-511 # e2e01 <_ZZL9init_specvE2tf+0x3d86d>
   4fcce:	000e3637          	lui	a2,0xe3
   4fcd2:	e4760613          	addi	a2,a2,-441 # e2e47 <_ZZL9init_specvE2tf+0x3d8b3>
   4fcd6:	30100593          	li	a1,769
   4fcda:	a0fef0ef          	jal	3f6e8 <_Z11fancy_abortPKciS0_>
0000000000050418 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info>:
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   50418:	7111                	addi	sp,sp,-256
   5041a:	fd86                	sd	ra,248(sp)
   5041c:	f9a2                	sd	s0,240(sp)
   5041e:	f5a6                	sd	s1,232(sp)
   50420:	f1ca                	sd	s2,224(sp)
   50422:	edce                	sd	s3,216(sp)
   50424:	e9d2                	sd	s4,208(sp)
   50426:	e5d6                	sd	s5,200(sp)
   50428:	e1da                	sd	s6,192(sp)
   5042a:	fd5e                	sd	s7,184(sp)
   5042c:	f962                	sd	s8,176(sp)
   5042e:	f566                	sd	s9,168(sp)
   50430:	f16a                	sd	s10,160(sp)
   50432:	ed6e                	sd	s11,152(sp)
   50434:	84b2                	mv	s1,a2
   50436:	89aa                	mv	s3,a0
_ZNK30diagnostic_source_print_policy11get_optionsEv():
   50438:	6188                	ld	a0,0(a1)
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   5043a:	00a9b023          	sd	a0,0(s3)
_ZNK13rich_location14get_line_tableEv():
   5043e:	6208                	ld	a0,0(a2)
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   50440:	00a9b423          	sd	a0,8(s3)
_ZNK30diagnostic_source_print_policy14get_file_cacheEv():
   50444:	7988                	ld	a0,48(a1)
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   50446:	0012e637          	lui	a2,0x12e
   5044a:	65860613          	addi	a2,a2,1624 # 12e658 <_ZTVN8text_art11ascii_themeE+0x10>
   5044e:	00a9b823          	sd	a0,16(s3)
   50452:	00c9bc23          	sd	a2,24(s3)
_ZNK30diagnostic_source_print_policy17get_diagram_themeEv():
   50456:	7d88                	ld	a0,56(a1)
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   50458:	e119                	bnez	a0,5045e <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x46>
   5045a:	01898513          	addi	a0,s3,24
   5045e:	02a9b023          	sd	a0,32(s3)
   50462:	02d9b423          	sd	a3,40(s3)
_ZNK24diagnostic_column_policy11get_tabstopEv():
   50466:	4d88                	lw	a0,24(a1)
   50468:	4605                	li	a2,1
_ZN12_GLOBAL__N_119char_display_policyC2EiPFijEPFvP14pretty_printerRK16cpp_decoded_charE():
   5046a:	000676b7          	lui	a3,0x67
   5046e:	6c868693          	addi	a3,a3,1736 # 676c8 <_Z11cpp_wcwidthj>
   50472:	00053737          	lui	a4,0x53
   50476:	1c470713          	addi	a4,a4,452 # 531c4 <_ZN12_GLOBAL__N_124default_print_decoded_chEP14pretty_printerRK16cpp_decoded_char>
   5047a:	02a9a823          	sw	a0,48(s3)
   5047e:	02c9aa23          	sw	a2,52(s3)
   50482:	02d9bc23          	sd	a3,56(s3)
   50486:	04e9b023          	sd	a4,64(s3)
_ZNK13rich_location18escape_on_output_pEv():
   5048a:	0874c503          	lbu	a0,135(s1)
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   5048e:	cd15                	beqz	a0,504ca <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0xb2>
   50490:	4511                	li	a0,4
   50492:	02a9aa23          	sw	a0,52(s3)
_ZNK30diagnostic_source_print_policy17get_escape_formatEv():
   50496:	41a8                	lw	a0,64(a1)
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   50498:	cd09                	beqz	a0,504b2 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x9a>
   5049a:	4585                	li	a1,1
   5049c:	46b51ee3          	bne	a0,a1,51118 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0xd00>
   504a0:	00053537          	lui	a0,0x53
   504a4:	2d850513          	addi	a0,a0,728 # 532d8 <_ZN12_GLOBAL__N_121escape_as_bytes_printEP14pretty_printerRK16cpp_decoded_char>
   504a8:	000535b7          	lui	a1,0x53
   504ac:	29a58593          	addi	a1,a1,666 # 5329a <_ZN12_GLOBAL__N_121escape_as_bytes_widthEj>
   504b0:	a809                	j	504c2 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0xaa>
   504b2:	00053537          	lui	a0,0x53
   504b6:	24650513          	addi	a0,a0,582 # 53246 <_ZN12_GLOBAL__N_123escape_as_unicode_printEP14pretty_printerRK16cpp_decoded_char>
   504ba:	000535b7          	lui	a1,0x53
   504be:	20e58593          	addi	a1,a1,526 # 5320e <_ZN12_GLOBAL__N_123escape_as_unicode_widthEj>
   504c2:	02b9bc23          	sd	a1,56(s3)
   504c6:	04a9b023          	sd	a0,64(s3)
   504ca:	03098413          	addi	s0,s3,48
   504ce:	8526                	mv	a0,s1
   504d0:	4581                	li	a1,0
   504d2:	51f2c0ef          	jal	7d1f0 <_ZNK13rich_location9get_rangeEj>
   504d6:	6108                	ld	a0,0(a0)
   504d8:	0109ba83          	ld	s5,16(s3)
   504dc:	04a9b423          	sd	a0,72(s3)
   504e0:	05098a13          	addi	s4,s3,80
   504e4:	1808                	addi	a0,sp,48
   504e6:	03010913          	addi	s2,sp,48
   504ea:	85a6                	mv	a1,s1
   504ec:	4601                	li	a2,0
   504ee:	5372c0ef          	jal	7d224 <_ZNK13rich_location21get_expanded_locationEj>
_ZN12_GLOBAL__N_123exploc_with_display_colC2ER10file_cacheRK17expanded_locationRK22cpp_char_column_policy15location_aspect():
   504f2:	cd927057          	vsetivli	zero,4,e64,m2,ta,ma
   504f6:	02097407          	vle64.v	v8,(s2)
   504fa:	1888                	addi	a0,sp,112
   504fc:	020a7427          	vse64.v	v8,(s4)
   50500:	02057427          	vse64.v	v8,(a0)
   50504:	188c                	addi	a1,sp,112
   50506:	8556                	mv	a0,s5
   50508:	8622                	mv	a2,s0
   5050a:	3a10d0ef          	jal	5e0aa <_Z31location_compute_display_columnR10file_cache17expanded_locationRK22cpp_char_column_policy>
   5050e:	55f2                	lw	a1,60(sp)
   50510:	06a9a823          	sw	a0,112(s3)
   50514:	02b05863          	blez	a1,50544 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x12c>
   50518:	0088                	addi	a0,sp,64
   5051a:	cd817057          	vsetivli	zero,2,e64,m1,ta,ma
   5051e:	02057407          	vle64.v	v8,(a0)
   50522:	7542                	ld	a0,48(sp)
   50524:	5662                	lw	a2,56(sp)
   50526:	1094                	addi	a3,sp,96
   50528:	0206f427          	vse64.v	v8,(a3)
   5052c:	15fd                	addi	a1,a1,-1
   5052e:	e8aa                	sd	a0,80(sp)
   50530:	ccb2                	sw	a2,88(sp)
   50532:	ceae                	sw	a1,92(sp)
   50534:	088c                	addi	a1,sp,80
   50536:	8556                	mv	a0,s5
   50538:	8622                	mv	a2,s0
   5053a:	3710d0ef          	jal	5e0aa <_Z31location_compute_display_columnR10file_cache17expanded_locationRK22cpp_char_column_policy>
   5053e:	0505                	addi	a0,a0,1
   50540:	06a9a823          	sw	a0,112(s3)
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   50544:	e422                	sd	s0,8(sp)
_ZNK17semi_embedded_vecI14location_rangeLi3EE5countEv():
   50546:	0084e403          	lwu	s0,8(s1)
   5054a:	80000b37          	lui	s6,0x80000
   5054e:	3b7d                	addiw	s6,s6,-1 # 7fffffff <__BSS_END__+0x7fe5829f>
_ZN3vecIN12_GLOBAL__N_112layout_rangeE7va_heap6vl_ptrE6createEj():
   50550:	0609bc23          	sd	zero,120(s3)
   50554:	c00d                	beqz	s0,50576 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x15e>
_ZN3vecIN12_GLOBAL__N_112layout_rangeE7va_heap8vl_embedE13embedded_sizeEj():
   50556:	00341513          	slli	a0,s0,0x3
   5055a:	00641593          	slli	a1,s0,0x6
   5055e:	8d89                	sub	a1,a1,a0
   50560:	05a1                	addi	a1,a1,8
_ZN7va_heap7reserveIN12_GLOBAL__N_112layout_rangeEEEvRP3vecIT_S_8vl_embedEjb():
   50562:	4501                	li	a0,0
   50564:	5d2510ef          	jal	a1b36 <xrealloc>
   50568:	06a9bc23          	sd	a0,120(s3)
_ZN3vecIN12_GLOBAL__N_112layout_rangeE7va_heap8vl_embedE13embedded_initEjjj():
   5056c:	016475b3          	and	a1,s0,s6
   50570:	c10c                	sw	a1,0(a0)
   50572:	00052223          	sw	zero,4(a0)
_ZNK17semi_embedded_vecIP10fixit_hintLi2EE5countEv():
   50576:	0a84e403          	lwu	s0,168(s1)
_ZN3vecIPK10fixit_hint7va_heap6vl_ptrE6createEj():
   5057a:	0809b023          	sd	zero,128(s3)
   5057e:	cc11                	beqz	s0,5059a <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x182>
_ZN3vecIPK10fixit_hint7va_heap8vl_embedE13embedded_sizeEj():
   50580:	00341593          	slli	a1,s0,0x3
   50584:	05a1                	addi	a1,a1,8
_ZN7va_heap7reserveIPK10fixit_hintEEvRP3vecIT_S_8vl_embedEjb():
   50586:	4501                	li	a0,0
   50588:	5ae510ef          	jal	a1b36 <xrealloc>
   5058c:	08a9b023          	sd	a0,128(s3)
_ZN3vecIPK10fixit_hint7va_heap8vl_embedE13embedded_initEjjj():
   50590:	016475b3          	and	a1,s0,s6
   50594:	c10c                	sw	a1,0(a0)
   50596:	00052223          	sw	zero,4(a0)
_ZNK17semi_embedded_vecI14location_rangeLi3EE5countEv():
   5059a:	4480                	lw	s0,8(s1)
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   5059c:	2405                	addiw	s0,s0,1
_ZN3vecIN12_GLOBAL__N_19line_spanE7va_heap6vl_ptrE6createEj():
   5059e:	0809b423          	sd	zero,136(s3)
   505a2:	c005                	beqz	s0,505c2 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x1aa>
_ZN3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE13embedded_sizeEj():
   505a4:	02041513          	slli	a0,s0,0x20
   505a8:	8175                	srli	a0,a0,0x1d
   505aa:	00850593          	addi	a1,a0,8
_ZN7va_heap7reserveIN12_GLOBAL__N_19line_spanEEEvRP3vecIT_S_8vl_embedEjb():
   505ae:	4501                	li	a0,0
   505b0:	586510ef          	jal	a1b36 <xrealloc>
   505b4:	08a9b423          	sd	a0,136(s3)
_ZN3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE13embedded_initEjjj():
   505b8:	016475b3          	and	a1,s0,s6
   505bc:	c10c                	sw	a1,0(a0)
   505be:	00052223          	sw	zero,4(a0)
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   505c2:	0809b823          	sd	zero,144(s3)
_ZNK13rich_location18escape_on_output_pEv():
   505c6:	0874c503          	lbu	a0,135(s1)
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   505ca:	08a98c23          	sb	a0,152(s3)
   505ce:	4488                	lw	a0,8(s1)
   505d0:	c105                	beqz	a0,505f0 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x1d8>
   505d2:	4401                	li	s0,0
   505d4:	8526                	mv	a0,s1
   505d6:	85a2                	mv	a1,s0
   505d8:	4192c0ef          	jal	7d1f0 <_ZNK13rich_location9get_rangeEj>
   505dc:	85aa                	mv	a1,a0
   505de:	854e                	mv	a0,s3
   505e0:	8622                	mv	a2,s0
   505e2:	4681                	li	a3,0
   505e4:	34d000ef          	jal	51130 <_ZN12_GLOBAL__N_16layout24maybe_add_location_rangeEPK14location_rangejb>
   505e8:	4488                	lw	a0,8(s1)
   505ea:	2405                	addiw	s0,s0,1
   505ec:	fea464e3          	bltu	s0,a0,505d4 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x1bc>
   505f0:	0a84a503          	lw	a0,168(s1)
   505f4:	4c05                	li	s8,1
   505f6:	020c1593          	slli	a1,s8,0x20
   505fa:	15f9                	addi	a1,a1,-2
   505fc:	e82e                	sd	a1,16(sp)
   505fe:	c22025f3          	csrr	a1,vlenb
   50602:	f42e                	sd	a1,40(sp)
   50604:	18050e63          	beqz	a0,507a0 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x388>
   50608:	4401                	li	s0,0
   5060a:	0b048b93          	addi	s7,s1,176
   5060e:	7522                	ld	a0,40(sp)
   50610:	00151d93          	slli	s11,a0,0x1
   50614:	8109                	srli	a0,a0,0x2
   50616:	e02a                	sd	a0,0(sp)
   50618:	ec5e                	sd	s7,24(sp)
   5061a:	a015                	j	5063e <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x226>
   5061c:	8aaa                	mv	s5,a0
   5061e:	6be2                	ld	s7,24(sp)
_ZN3vecIPK10fixit_hint7va_heap8vl_embedE10quick_pushERKS2_():
   50620:	004ae503          	lwu	a0,4(s5)
   50624:	00351593          	slli	a1,a0,0x3
   50628:	0505                	addi	a0,a0,1
_ZN3vecIPK10fixit_hint7va_heap8vl_embedE7addressEv():
   5062a:	95d6                	add	a1,a1,s5
_ZN3vecIPK10fixit_hint7va_heap8vl_embedE10quick_pushERKS2_():
   5062c:	00aaa223          	sw	a0,4(s5)
   50630:	0125b423          	sd	s2,8(a1)
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   50634:	0a84a503          	lw	a0,168(s1)
   50638:	2405                	addiw	s0,s0,1
   5063a:	16a47363          	bgeu	s0,a0,507a0 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x388>
   5063e:	008c4663          	blt	s8,s0,5064a <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x232>
_ZNK17semi_embedded_vecIP10fixit_hintLi2EEixEi():
   50642:	00341513          	slli	a0,s0,0x3
   50646:	955e                	add	a0,a0,s7
   50648:	a031                	j	50654 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x23c>
   5064a:	64e8                	ld	a0,200(s1)
   5064c:	00341593          	slli	a1,s0,0x3
   50650:	952e                	add	a0,a0,a1
   50652:	1541                	addi	a0,a0,-16
_ZNK13rich_location14get_fixit_hintEi():
   50654:	00053903          	ld	s2,0(a0)
_ZNK10fixit_hint13get_start_locEv():
   50658:	00093583          	ld	a1,0(s2)
_ZN12_GLOBAL__N_16layout21validate_fixit_hint_pEPK10fixit_hint():
   5065c:	1888                	addi	a0,sp,112
   5065e:	0410d0ef          	jal	5de9e <_Z15expand_locationm>
   50662:	7546                	ld	a0,112(sp)
   50664:	000a3583          	ld	a1,0(s4)
   50668:	fcb516e3          	bne	a0,a1,50634 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x21c>
_ZNK10fixit_hint12get_next_locEv():
   5066c:	00893583          	ld	a1,8(s2)
_ZN12_GLOBAL__N_16layout21validate_fixit_hint_pEPK10fixit_hint():
   50670:	1888                	addi	a0,sp,112
   50672:	02d0d0ef          	jal	5de9e <_Z15expand_locationm>
   50676:	7546                	ld	a0,112(sp)
   50678:	000a3583          	ld	a1,0(s4)
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   5067c:	fab51ce3          	bne	a0,a1,50634 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x21c>
_ZNK3vecIPK10fixit_hint7va_heap6vl_ptrE5spaceEi():
   50680:	0809ba83          	ld	s5,128(s3)
   50684:	020a8a63          	beqz	s5,506b8 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x2a0>
_ZNK3vecIPK10fixit_hint7va_heap8vl_embedE5spaceEj():
   50688:	000aa583          	lw	a1,0(s5)
   5068c:	004aa603          	lw	a2,4(s5)
   50690:	0165f533          	and	a0,a1,s6
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   50694:	f8c516e3          	bne	a0,a2,50620 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x208>
   50698:	0a05c763          	bltz	a1,50746 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x32e>
   5069c:	0015059b          	addiw	a1,a0,1
   506a0:	813eb0ef          	jal	3beb2 <_ZN10vec_prefix22calculate_allocation_1Ejj>
   506a4:	0809b583          	ld	a1,128(s3)
   506a8:	8caa                	mv	s9,a0
   506aa:	c9c5                	beqz	a1,5075a <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x342>
   506ac:	852e                	mv	a0,a1
   506ae:	f002                	sd	zero,32(sp)
_ZNK3vecIPK10fixit_hint7va_heap8vl_embedE6lengthEv():
   506b0:	0045ab83          	lw	s7,4(a1)
   506b4:	4d01                	li	s10,0
   506b6:	a819                	j	506cc <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x2b4>
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   506b8:	f002                	sd	zero,32(sp)
   506ba:	4c85                	li	s9,1
   506bc:	4511                	li	a0,4
   506be:	01956363          	bltu	a0,s9,506c4 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x2ac>
   506c2:	4c91                	li	s9,4
   506c4:	4501                	li	a0,0
   506c6:	4b81                	li	s7,0
   506c8:	01503d33          	snez	s10,s5
_ZN3vecIPK10fixit_hint7va_heap8vl_embedE13embedded_sizeEj():
   506cc:	020c9593          	slli	a1,s9,0x20
   506d0:	81f5                	srli	a1,a1,0x1d
   506d2:	05a1                	addi	a1,a1,8
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   506d4:	462510ef          	jal	a1b36 <xrealloc>
   506d8:	08a9b023          	sd	a0,128(s3)
_ZN3vecIPK10fixit_hint7va_heap8vl_embedE13embedded_initEjjj():
   506dc:	016cf5b3          	and	a1,s9,s6
   506e0:	c10c                	sw	a1,0(a0)
   506e2:	01752223          	sw	s7,4(a0)
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   506e6:	0809b503          	ld	a0,128(s3)
   506ea:	f20d09e3          	beqz	s10,5061c <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x204>
   506ee:	7282                	ld	t0,32(sp)
   506f0:	04028563          	beqz	t0,5073a <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x322>
   506f4:	45a1                	li	a1,8
   506f6:	6882                	ld	a7,0(sp)
   506f8:	8646                	mv	a2,a7
   506fa:	0115e363          	bltu	a1,a7,50700 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x2e8>
   506fe:	4621                	li	a2,8
   50700:	02029593          	slli	a1,t0,0x20
   50704:	9181                	srli	a1,a1,0x20
   50706:	6be2                	ld	s7,24(sp)
   50708:	00c5e663          	bltu	a1,a2,50714 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x2fc>
   5070c:	41550633          	sub	a2,a0,s5
   50710:	05b67a63          	bgeu	a2,s11,50764 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x34c>
   50714:	8616                	mv	a2,t0
   50716:	86d6                	mv	a3,s5
   50718:	00868593          	addi	a1,a3,8
   5071c:	0521                	addi	a0,a0,8
   5071e:	167d                	addi	a2,a2,-1
   50720:	1602                	slli	a2,a2,0x20
   50722:	8275                	srli	a2,a2,0x1d
   50724:	9636                	add	a2,a2,a3
   50726:	0641                	addi	a2,a2,16
   50728:	6194                	ld	a3,0(a1)
   5072a:	05a1                	addi	a1,a1,8
   5072c:	e114                	sd	a3,0(a0)
   5072e:	0521                	addi	a0,a0,8
   50730:	fec59ce3          	bne	a1,a2,50728 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x310>
   50734:	0809b503          	ld	a0,128(s3)
   50738:	a011                	j	5073c <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x324>
   5073a:	6be2                	ld	s7,24(sp)
   5073c:	00552223          	sw	t0,4(a0)
   50740:	0809ba83          	ld	s5,128(s3)
   50744:	bdf1                	j	50620 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x208>
   50746:	0809b023          	sd	zero,128(s3)
_ZNK3vecIPK10fixit_hint7va_heap8vl_embedE6lengthEv():
   5074a:	004aac83          	lw	s9,4(s5)
   5074e:	f066                	sd	s9,32(sp)
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   50750:	2c85                	addiw	s9,s9,1
   50752:	4511                	li	a0,4
   50754:	f79577e3          	bgeu	a0,s9,506c2 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x2aa>
   50758:	b7b5                	j	506c4 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x2ac>
   5075a:	f002                	sd	zero,32(sp)
   5075c:	4d01                	li	s10,0
   5075e:	4501                	li	a0,0
   50760:	4b81                	li	s7,0
   50762:	b7ad                	j	506cc <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x2b4>
   50764:	7622                	ld	a2,40(sp)
   50766:	820d                	srli	a2,a2,0x3
   50768:	00850793          	addi	a5,a0,8
   5076c:	66c2                	ld	a3,16(sp)
   5076e:	02d60633          	mul	a2,a2,a3
   50772:	00b67833          	and	a6,a2,a1
   50776:	4102863b          	subw	a2,t0,a6
   5077a:	00381713          	slli	a4,a6,0x3
   5077e:	00ea86b3          	add	a3,s5,a4
   50782:	953a                	add	a0,a0,a4
   50784:	0aa1                	addi	s5,s5,8
   50786:	8742                	mv	a4,a6
   50788:	228af407          	vl2re64.v	v8,(s5)
   5078c:	41170733          	sub	a4,a4,a7
   50790:	22878427          	vs2r.v	v8,(a5)
   50794:	97ee                	add	a5,a5,s11
   50796:	9aee                	add	s5,s5,s11
   50798:	fb65                	bnez	a4,50788 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x370>
   5079a:	f6b81fe3          	bne	a6,a1,50718 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x300>
   5079e:	bf59                	j	50734 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x31c>
_ZN3vecIPK10fixit_hint7va_heap6vl_ptrE5qsortEPFiPKvS7_E():
   507a0:	0809b503          	ld	a0,128(s3)
   507a4:	cd11                	beqz	a0,507c0 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x3a8>
_ZNK3vecIPK10fixit_hint7va_heap8vl_embedE6lengthEv():
   507a6:	00456583          	lwu	a1,4(a0)
   507aa:	4609                	li	a2,2
_ZN3vecIPK10fixit_hint7va_heap8vl_embedE5qsortEPFiPKvS7_E():
   507ac:	00c5ea63          	bltu	a1,a2,507c0 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x3a8>
_ZN3vecIPK10fixit_hint7va_heap8vl_embedE7addressEv():
   507b0:	0521                	addi	a0,a0,8
_ZN3vecIPK10fixit_hint7va_heap8vl_embedE5qsortEPFiPKvS7_E():
   507b2:	000536b7          	lui	a3,0x53
   507b6:	1b868693          	addi	a3,a3,440 # 531b8 <_ZN12_GLOBAL__N_19fixit_cmpEPKvS1_>
   507ba:	4621                	li	a2,8
   507bc:	7d70e0ef          	jal	5f792 <_Z9gcc_qsortPvmmPFiPKvS1_E>
_ZNK3vecIN12_GLOBAL__N_19line_spanE7va_heap6vl_ptrE6lengthEv():
   507c0:	0889b503          	ld	a0,136(s3)
   507c4:	c501                	beqz	a0,507cc <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x3b4>
_ZNK3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE6lengthEv():
   507c6:	4148                	lw	a0,4(a0)
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   507c8:	100514e3          	bnez	a0,510d0 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0xcb8>
   507cc:	0789b503          	ld	a0,120(s3)
   507d0:	c909                	beqz	a0,507e2 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x3ca>
_ZNK3vecIN12_GLOBAL__N_112layout_rangeE7va_heap8vl_embedE6lengthEv():
   507d2:	4140                	lw	s0,4(a0)
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   507d4:	2405                	addiw	s0,s0,1
   507d6:	e809                	bnez	s0,507e8 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x3d0>
   507d8:	4a01                	li	s4,0
   507da:	0589a903          	lw	s2,88(s3)
   507de:	4491                	li	s1,4
   507e0:	a83d                	j	5081e <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x406>
   507e2:	4505                	li	a0,1
   507e4:	4405                	li	s0,1
   507e6:	a021                	j	507ee <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x3d6>
   507e8:	02041513          	slli	a0,s0,0x20
   507ec:	9101                	srli	a0,a0,0x20
_ZN3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE13embedded_sizeEj():
   507ee:	050e                	slli	a0,a0,0x3
   507f0:	00850593          	addi	a1,a0,8
_ZN7va_heap7reserveIN12_GLOBAL__N_19line_spanEEEvRP3vecIT_S_8vl_embedEjb():
   507f4:	4501                	li	a0,0
   507f6:	340510ef          	jal	a1b36 <xrealloc>
   507fa:	8a2a                	mv	s4,a0
_ZN3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE13embedded_initEjjj():
   507fc:	01647533          	and	a0,s0,s6
   50800:	00aa2023          	sw	a0,0(s4)
   50804:	000a2223          	sw	zero,4(s4)
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   50808:	0589a903          	lw	s2,88(s3)
   5080c:	c119                	beqz	a0,50812 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x3fa>
   5080e:	4401                	li	s0,0
   50810:	a035                	j	5083c <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x424>
   50812:	4585                	li	a1,1
   50814:	e9eeb0ef          	jal	3beb2 <_ZN10vec_prefix22calculate_allocation_1Ejj>
_ZNK3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE6lengthEv():
   50818:	004a2403          	lw	s0,4(s4)
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   5081c:	84aa                	mv	s1,a0
_ZN3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE13embedded_sizeEj():
   5081e:	02049513          	slli	a0,s1,0x20
   50822:	8175                	srli	a0,a0,0x1d
   50824:	00850593          	addi	a1,a0,8
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   50828:	8552                	mv	a0,s4
   5082a:	30c510ef          	jal	a1b36 <xrealloc>
   5082e:	8a2a                	mv	s4,a0
_ZN3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE13embedded_initEjjj():
   50830:	0164f533          	and	a0,s1,s6
   50834:	00aa2023          	sw	a0,0(s4)
   50838:	008a2223          	sw	s0,4(s4)
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   5083c:	4a81                	li	s5,0
_ZN3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE10quick_pushERKS1_():
   5083e:	02041513          	slli	a0,s0,0x20
   50842:	2405                	addiw	s0,s0,1
   50844:	8175                	srli	a0,a0,0x1d
_ZN3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE7addressEv():
   50846:	9552                	add	a0,a0,s4
_ZN3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE10quick_pushERKS1_():
   50848:	008a2223          	sw	s0,4(s4)
   5084c:	01252423          	sw	s2,8(a0)
   50850:	01252623          	sw	s2,12(a0)
   50854:	7522                	ld	a0,40(sp)
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   50856:	00151c13          	slli	s8,a0,0x1
   5085a:	00255913          	srli	s2,a0,0x2
   5085e:	a015                	j	50882 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x46a>
   50860:	8552                	mv	a0,s4
   50862:	1d02                	slli	s10,s10,0x20
   50864:	1c82                	slli	s9,s9,0x20
   50866:	02041593          	slli	a1,s0,0x20
   5086a:	2405                	addiw	s0,s0,1
   5086c:	020d5613          	srli	a2,s10,0x20
   50870:	020cd693          	srli	a3,s9,0x20
   50874:	81f5                	srli	a1,a1,0x1d
_ZN3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE7addressEv():
   50876:	95aa                	add	a1,a1,a0
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   50878:	c590                	sw	a2,8(a1)
   5087a:	c5d4                	sw	a3,12(a1)
   5087c:	c140                	sw	s0,4(a0)
   5087e:	0a85                	addi	s5,s5,1
   50880:	8a2a                	mv	s4,a0
_ZNK3vecIN12_GLOBAL__N_112layout_rangeE7va_heap6vl_ptrE6lengthEv():
   50882:	0789b503          	ld	a0,120(s3)
   50886:	c511                	beqz	a0,50892 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x47a>
_ZNK3vecIN12_GLOBAL__N_112layout_rangeE7va_heap8vl_embedE6lengthEv():
   50888:	00456583          	lwu	a1,4(a0)
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   5088c:	00bae563          	bltu	s5,a1,50896 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x47e>
   50890:	a8ed                	j	5098a <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x572>
   50892:	0e0afc63          	bgeu	s5,zero,5098a <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x572>
_ZN3vecIN12_GLOBAL__N_112layout_rangeE7va_heap8vl_embedEixEj():
   50896:	003a9593          	slli	a1,s5,0x3
   5089a:	006a9613          	slli	a2,s5,0x6
   5089e:	8e0d                	sub	a2,a2,a1
_ZN3vecIN12_GLOBAL__N_112layout_rangeE7va_heap8vl_embedE7addressEv():
   508a0:	9532                	add	a0,a0,a2
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   508a2:	00852d03          	lw	s10,8(a0)
   508a6:	01452c83          	lw	s9,20(a0)
   508aa:	71acef63          	bltu	s9,s10,50fc8 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0xbb0>
_ZNK3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE5spaceEj():
   508ae:	000a2483          	lw	s1,0(s4)
   508b2:	0164f533          	and	a0,s1,s6
_ZN3vecIN12_GLOBAL__N_19line_spanE7va_heap6vl_ptrE7reserveEjb():
   508b6:	fa8515e3          	bne	a0,s0,50860 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x448>
   508ba:	0004cd63          	bltz	s1,508d4 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x4bc>
_ZN7va_heap7reserveIN12_GLOBAL__N_19line_spanEEEvRP3vecIT_S_8vl_embedEjb():
   508be:	0014059b          	addiw	a1,s0,1
   508c2:	8522                	mv	a0,s0
   508c4:	deeeb0ef          	jal	3beb2 <_ZN10vec_prefix22calculate_allocation_1Ejj>
   508c8:	8baa                	mv	s7,a0
   508ca:	4401                	li	s0,0
_ZNK3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE6lengthEv():
   508cc:	004a2d83          	lw	s11,4(s4)
   508d0:	8552                	mv	a0,s4
   508d2:	a809                	j	508e4 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x4cc>
_ZN7va_heap7reserveIN12_GLOBAL__N_19line_spanEEEvRP3vecIT_S_8vl_embedEjb():
   508d4:	450d                	li	a0,3
   508d6:	8ba2                	mv	s7,s0
   508d8:	00856363          	bltu	a0,s0,508de <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x4c6>
   508dc:	4b8d                	li	s7,3
   508de:	4501                	li	a0,0
   508e0:	4d81                	li	s11,0
   508e2:	0b85                	addi	s7,s7,1
_ZN3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE13embedded_sizeEj():
   508e4:	020b9593          	slli	a1,s7,0x20
   508e8:	81f5                	srli	a1,a1,0x1d
   508ea:	05a1                	addi	a1,a1,8
_ZN7va_heap7reserveIN12_GLOBAL__N_19line_spanEEEvRP3vecIT_S_8vl_embedEjb():
   508ec:	24a510ef          	jal	a1b36 <xrealloc>
_ZN3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE13embedded_initEjjj():
   508f0:	016bf5b3          	and	a1,s7,s6
   508f4:	c10c                	sw	a1,0(a0)
   508f6:	01b52223          	sw	s11,4(a0)
_ZN3vecIN12_GLOBAL__N_19line_spanE7va_heap6vl_ptrE7reserveEjb():
   508fa:	0004c463          	bltz	s1,50902 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x4ea>
   508fe:	846e                	mv	s0,s11
   50900:	b78d                	j	50862 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x44a>
   50902:	c421                	beqz	s0,5094a <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x532>
   50904:	45a1                	li	a1,8
   50906:	864a                	mv	a2,s2
   50908:	0125e363          	bltu	a1,s2,5090e <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x4f6>
   5090c:	4621                	li	a2,8
   5090e:	02041593          	slli	a1,s0,0x20
   50912:	9181                	srli	a1,a1,0x20
   50914:	00c5e663          	bltu	a1,a2,50920 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x508>
   50918:	41450633          	sub	a2,a0,s4
   5091c:	03867963          	bgeu	a2,s8,5094e <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x536>
   50920:	8622                	mv	a2,s0
   50922:	86d2                	mv	a3,s4
   50924:	872a                	mv	a4,a0
   50926:	00868593          	addi	a1,a3,8
   5092a:	0721                	addi	a4,a4,8
   5092c:	167d                	addi	a2,a2,-1
   5092e:	1602                	slli	a2,a2,0x20
   50930:	8275                	srli	a2,a2,0x1d
   50932:	9636                	add	a2,a2,a3
   50934:	0641                	addi	a2,a2,16
   50936:	0005e683          	lwu	a3,0(a1)
   5093a:	0045e783          	lwu	a5,4(a1)
   5093e:	05a1                	addi	a1,a1,8
   50940:	c314                	sw	a3,0(a4)
   50942:	c35c                	sw	a5,4(a4)
   50944:	0721                	addi	a4,a4,8
   50946:	fec598e3          	bne	a1,a2,50936 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x51e>
   5094a:	c140                	sw	s0,4(a0)
   5094c:	bf19                	j	50862 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x44a>
   5094e:	7622                	ld	a2,40(sp)
   50950:	820d                	srli	a2,a2,0x3
   50952:	00850493          	addi	s1,a0,8
   50956:	66c2                	ld	a3,16(sp)
   50958:	02d60633          	mul	a2,a2,a3
   5095c:	00b67833          	and	a6,a2,a1
   50960:	4104063b          	subw	a2,s0,a6
   50964:	00381713          	slli	a4,a6,0x3
   50968:	00ea06b3          	add	a3,s4,a4
   5096c:	972a                	add	a4,a4,a0
   5096e:	0a21                	addi	s4,s4,8
   50970:	87c2                	mv	a5,a6
   50972:	228a0407          	vl2r.v	v8,(s4)
   50976:	412787b3          	sub	a5,a5,s2
   5097a:	22848427          	vs2r.v	v8,(s1)
   5097e:	94e2                	add	s1,s1,s8
   50980:	9a62                	add	s4,s4,s8
   50982:	fbe5                	bnez	a5,50972 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x55a>
   50984:	fab811e3          	bne	a6,a1,50926 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x50e>
   50988:	b7c9                	j	5094a <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x532>
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   5098a:	4a81                	li	s5,0
   5098c:	80000537          	lui	a0,0x80000
   50990:	3579                	addiw	a0,a0,-2 # 7ffffffe <__BSS_END__+0x7fe5829e>
   50992:	f02a                	sd	a0,32(sp)
   50994:	7522                	ld	a0,40(sp)
   50996:	00255d13          	srli	s10,a0,0x2
   5099a:	a03d                	j	509c8 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x5b0>
   5099c:	842a                	mv	s0,a0
   5099e:	8552                	mv	a0,s4
   509a0:	1d82                	slli	s11,s11,0x20
   509a2:	1902                	slli	s2,s2,0x20
   509a4:	02041593          	slli	a1,s0,0x20
   509a8:	0405                	addi	s0,s0,1
   509aa:	020dd613          	srli	a2,s11,0x20
   509ae:	02095693          	srli	a3,s2,0x20
   509b2:	81f5                	srli	a1,a1,0x1d
   509b4:	1602                	slli	a2,a2,0x20
_ZN3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE7addressEv():
   509b6:	95aa                	add	a1,a1,a0
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   509b8:	8e55                	or	a2,a2,a3
   509ba:	02065693          	srli	a3,a2,0x20
   509be:	c590                	sw	a2,8(a1)
   509c0:	c5d4                	sw	a3,12(a1)
   509c2:	c140                	sw	s0,4(a0)
   509c4:	0a85                	addi	s5,s5,1
   509c6:	8a2a                	mv	s4,a0
_ZNK3vecIPK10fixit_hint7va_heap6vl_ptrE6lengthEv():
   509c8:	0809b503          	ld	a0,128(s3)
   509cc:	c511                	beqz	a0,509d8 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x5c0>
_ZNK3vecIPK10fixit_hint7va_heap8vl_embedE6lengthEv():
   509ce:	00456583          	lwu	a1,4(a0)
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   509d2:	00bae563          	bltu	s5,a1,509dc <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x5c4>
   509d6:	aa19                	j	50aec <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x6d4>
   509d8:	100afa63          	bgeu	s5,zero,50aec <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x6d4>
_ZN3vecIPK10fixit_hint7va_heap8vl_embedEixEj():
   509dc:	003a9593          	slli	a1,s5,0x3
_ZN3vecIPK10fixit_hint7va_heap8vl_embedE7addressEv():
   509e0:	952e                	add	a0,a0,a1
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   509e2:	6500                	ld	s0,8(a0)
   509e4:	5e040e63          	beqz	s0,50fe0 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0xbc8>
_ZNK10fixit_hint13get_start_locEv():
   509e8:	600c                	ld	a1,0(s0)
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   509ea:	1888                	addi	a0,sp,112
   509ec:	4b20d0ef          	jal	5de9e <_Z15expand_locationm>
   509f0:	54e6                	lw	s1,120(sp)
   509f2:	8522                	mv	a0,s0
   509f4:	3742d0ef          	jal	7dd68 <_ZNK10fixit_hint19ends_with_newline_pEv>
   509f8:	0024a613          	slti	a2,s1,2
_ZNK10fixit_hint12get_next_locEv():
   509fc:	640c                	ld	a1,8(s0)
   509fe:	00164613          	xori	a2,a2,1
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   50a02:	8d71                	and	a0,a0,a2
   50a04:	40a4893b          	subw	s2,s1,a0
   50a08:	1888                	addi	a0,sp,112
   50a0a:	4940d0ef          	jal	5de9e <_Z15expand_locationm>
   50a0e:	5de6                	lw	s11,120(sp)
   50a10:	5f2de463          	bltu	s11,s2,50ff8 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0xbe0>
_ZNK3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE5spaceEj():
   50a14:	000a2483          	lw	s1,0(s4)
   50a18:	004a2503          	lw	a0,4(s4)
   50a1c:	0164f433          	and	s0,s1,s6
_ZN3vecIN12_GLOBAL__N_19line_spanE7va_heap6vl_ptrE7reserveEjb():
   50a20:	f6a41ee3          	bne	s0,a0,5099c <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x584>
   50a24:	0004cd63          	bltz	s1,50a3e <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x626>
_ZN7va_heap7reserveIN12_GLOBAL__N_19line_spanEEEvRP3vecIT_S_8vl_embedEjb():
   50a28:	0014059b          	addiw	a1,s0,1
   50a2c:	8522                	mv	a0,s0
   50a2e:	c84eb0ef          	jal	3beb2 <_ZN10vec_prefix22calculate_allocation_1Ejj>
   50a32:	8baa                	mv	s7,a0
   50a34:	4401                	li	s0,0
_ZNK3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE6lengthEv():
   50a36:	004a2c83          	lw	s9,4(s4)
   50a3a:	8552                	mv	a0,s4
   50a3c:	a809                	j	50a4e <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x636>
_ZN7va_heap7reserveIN12_GLOBAL__N_19line_spanEEEvRP3vecIT_S_8vl_embedEjb():
   50a3e:	450d                	li	a0,3
   50a40:	8ba2                	mv	s7,s0
   50a42:	00856363          	bltu	a0,s0,50a48 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x630>
   50a46:	4b8d                	li	s7,3
   50a48:	4501                	li	a0,0
   50a4a:	4c81                	li	s9,0
   50a4c:	0b85                	addi	s7,s7,1
_ZN3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE13embedded_sizeEj():
   50a4e:	020b9593          	slli	a1,s7,0x20
   50a52:	81f5                	srli	a1,a1,0x1d
   50a54:	05a1                	addi	a1,a1,8
_ZN7va_heap7reserveIN12_GLOBAL__N_19line_spanEEEvRP3vecIT_S_8vl_embedEjb():
   50a56:	0e0510ef          	jal	a1b36 <xrealloc>
_ZN3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE13embedded_initEjjj():
   50a5a:	016bf5b3          	and	a1,s7,s6
   50a5e:	c10c                	sw	a1,0(a0)
   50a60:	01952223          	sw	s9,4(a0)
_ZN3vecIN12_GLOBAL__N_19line_spanE7va_heap6vl_ptrE7reserveEjb():
   50a64:	0004c463          	bltz	s1,50a6c <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x654>
   50a68:	8466                	mv	s0,s9
   50a6a:	bf1d                	j	509a0 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x588>
   50a6c:	c029                	beqz	s0,50aae <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x696>
   50a6e:	4621                	li	a2,8
   50a70:	85ea                	mv	a1,s10
   50a72:	01a66363          	bltu	a2,s10,50a78 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x660>
   50a76:	45a1                	li	a1,8
   50a78:	00b46663          	bltu	s0,a1,50a84 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x66c>
   50a7c:	414505b3          	sub	a1,a0,s4
   50a80:	0385f963          	bgeu	a1,s8,50ab2 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x69a>
   50a84:	85a2                	mv	a1,s0
   50a86:	8652                	mv	a2,s4
   50a88:	86aa                	mv	a3,a0
   50a8a:	00860713          	addi	a4,a2,8
   50a8e:	06a1                	addi	a3,a3,8
   50a90:	15fd                	addi	a1,a1,-1
   50a92:	1582                	slli	a1,a1,0x20
   50a94:	81f5                	srli	a1,a1,0x1d
   50a96:	95b2                	add	a1,a1,a2
   50a98:	05c1                	addi	a1,a1,16
   50a9a:	00076603          	lwu	a2,0(a4)
   50a9e:	00476783          	lwu	a5,4(a4)
   50aa2:	0721                	addi	a4,a4,8
   50aa4:	c290                	sw	a2,0(a3)
   50aa6:	c2dc                	sw	a5,4(a3)
   50aa8:	06a1                	addi	a3,a3,8
   50aaa:	feb718e3          	bne	a4,a1,50a9a <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x682>
   50aae:	c140                	sw	s0,4(a0)
   50ab0:	bdc5                	j	509a0 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x588>
   50ab2:	75a2                	ld	a1,40(sp)
   50ab4:	818d                	srli	a1,a1,0x3
   50ab6:	00850793          	addi	a5,a0,8
   50aba:	7602                	ld	a2,32(sp)
   50abc:	02c584b3          	mul	s1,a1,a2
   50ac0:	8ce1                	and	s1,s1,s0
   50ac2:	409405bb          	subw	a1,s0,s1
   50ac6:	00349693          	slli	a3,s1,0x3
   50aca:	00da0633          	add	a2,s4,a3
   50ace:	96aa                	add	a3,a3,a0
   50ad0:	0a21                	addi	s4,s4,8
   50ad2:	8726                	mv	a4,s1
   50ad4:	228a0407          	vl2r.v	v8,(s4)
   50ad8:	41a70733          	sub	a4,a4,s10
   50adc:	22878427          	vs2r.v	v8,(a5)
   50ae0:	97e2                	add	a5,a5,s8
   50ae2:	9a62                	add	s4,s4,s8
   50ae4:	fb65                	bnez	a4,50ad4 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x6bc>
   50ae6:	fa8492e3          	bne	s1,s0,50a8a <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x672>
   50aea:	b7d1                	j	50aae <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x696>
_ZNK3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE6lengthEv():
   50aec:	004a6583          	lwu	a1,4(s4)
   50af0:	4509                	li	a0,2
_ZN3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE5qsortEPFiPKvS6_E():
   50af2:	00a5ed63          	bltu	a1,a0,50b0c <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x6f4>
_ZN3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE7addressEv():
   50af6:	008a0513          	addi	a0,s4,8
_ZN3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE5qsortEPFiPKvS6_E():
   50afa:	000536b7          	lui	a3,0x53
   50afe:	38868693          	addi	a3,a3,904 # 53388 <_ZN12_GLOBAL__N_19line_span10comparatorEPKvS2_>
   50b02:	4621                	li	a2,8
   50b04:	48f0e0ef          	jal	5f792 <_Z9gcc_qsortPvmmPFiPKvS1_E>
_ZNK3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE6lengthEv():
   50b08:	004a2583          	lw	a1,4(s4)
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   50b0c:	2581                	sext.w	a1,a1
   50b0e:	5a058563          	beqz	a1,510b8 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0xca0>
_ZNK3vecIN12_GLOBAL__N_19line_spanE7va_heap6vl_ptrE5spaceEi():
   50b12:	0889b483          	ld	s1,136(s3)
   50b16:	c885                	beqz	s1,50b46 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x72e>
_ZNK3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE5spaceEj():
   50b18:	408c                	lw	a1,0(s1)
   50b1a:	40d0                	lw	a2,4(s1)
   50b1c:	0165f533          	and	a0,a1,s6
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   50b20:	0ac51d63          	bne	a0,a2,50bda <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x7c2>
   50b24:	3a05c763          	bltz	a1,50ed2 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0xaba>
   50b28:	0015059b          	addiw	a1,a0,1
   50b2c:	b86eb0ef          	jal	3beb2 <_ZN10vec_prefix22calculate_allocation_1Ejj>
   50b30:	0889b583          	ld	a1,136(s3)
   50b34:	842a                	mv	s0,a0
   50b36:	40058663          	beqz	a1,50f42 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0xb2a>
   50b3a:	852e                	mv	a0,a1
   50b3c:	4901                	li	s2,0
_ZNK3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE6lengthEv():
   50b3e:	0045aa83          	lw	s5,4(a1)
   50b42:	4b81                	li	s7,0
   50b44:	a819                	j	50b5a <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x742>
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   50b46:	4901                	li	s2,0
   50b48:	4405                	li	s0,1
   50b4a:	4511                	li	a0,4
   50b4c:	00856363          	bltu	a0,s0,50b52 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x73a>
   50b50:	4411                	li	s0,4
   50b52:	4501                	li	a0,0
   50b54:	4a81                	li	s5,0
   50b56:	00903bb3          	snez	s7,s1
_ZN3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE13embedded_sizeEj():
   50b5a:	02041593          	slli	a1,s0,0x20
   50b5e:	81f5                	srli	a1,a1,0x1d
   50b60:	05a1                	addi	a1,a1,8
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   50b62:	7d5500ef          	jal	a1b36 <xrealloc>
   50b66:	08a9b423          	sd	a0,136(s3)
_ZN3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE13embedded_initEjjj():
   50b6a:	016475b3          	and	a1,s0,s6
   50b6e:	c10c                	sw	a1,0(a0)
   50b70:	01552223          	sw	s5,4(a0)
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   50b74:	0889b603          	ld	a2,136(s3)
   50b78:	060b8063          	beqz	s7,50bd8 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x7c0>
   50b7c:	04090963          	beqz	s2,50bce <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x7b6>
   50b80:	02091513          	slli	a0,s2,0x20
   50b84:	75a2                	ld	a1,40(sp)
   50b86:	8189                	srli	a1,a1,0x2
   50b88:	4741                	li	a4,16
   50b8a:	9101                	srli	a0,a0,0x20
   50b8c:	86ae                	mv	a3,a1
   50b8e:	00b76363          	bltu	a4,a1,50b94 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x77c>
   50b92:	46c1                	li	a3,16
   50b94:	00d56663          	bltu	a0,a3,50ba0 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x788>
   50b98:	409606b3          	sub	a3,a2,s1
   50b9c:	3f86f963          	bgeu	a3,s8,50f8e <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0xb76>
   50ba0:	86ca                	mv	a3,s2
   50ba2:	8726                	mv	a4,s1
   50ba4:	00870513          	addi	a0,a4,8
   50ba8:	0621                	addi	a2,a2,8
   50baa:	16fd                	addi	a3,a3,-1
   50bac:	1682                	slli	a3,a3,0x20
   50bae:	82f5                	srli	a3,a3,0x1d
   50bb0:	00e685b3          	add	a1,a3,a4
   50bb4:	05c1                	addi	a1,a1,16
   50bb6:	00056683          	lwu	a3,0(a0)
   50bba:	00456703          	lwu	a4,4(a0)
   50bbe:	0521                	addi	a0,a0,8
   50bc0:	c214                	sw	a3,0(a2)
   50bc2:	c258                	sw	a4,4(a2)
   50bc4:	0621                	addi	a2,a2,8
   50bc6:	feb518e3          	bne	a0,a1,50bb6 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x79e>
   50bca:	0889b603          	ld	a2,136(s3)
   50bce:	01262223          	sw	s2,4(a2)
   50bd2:	0889b483          	ld	s1,136(s3)
   50bd6:	a011                	j	50bda <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x7c2>
   50bd8:	84b2                	mv	s1,a2
_ZN3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE10quick_pushERKS1_():
   50bda:	0044e503          	lwu	a0,4(s1)
   50bde:	00150593          	addi	a1,a0,1
   50be2:	c0cc                	sw	a1,4(s1)
   50be4:	008a6583          	lwu	a1,8(s4)
   50be8:	00ca6603          	lwu	a2,12(s4)
   50bec:	050e                	slli	a0,a0,0x3
_ZN3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE7addressEv():
   50bee:	9526                	add	a0,a0,s1
_ZN3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE10quick_pushERKS1_():
   50bf0:	c50c                	sw	a1,8(a0)
   50bf2:	c550                	sw	a2,12(a0)
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   50bf4:	004a2503          	lw	a0,4(s4)
   50bf8:	4589                	li	a1,2
   50bfa:	18b56163          	bltu	a0,a1,50d7c <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x964>
   50bfe:	7522                	ld	a0,40(sp)
   50c00:	8109                	srli	a0,a0,0x2
   50c02:	ec2a                	sd	a0,24(sp)
   50c04:	4485                	li	s1,1
   50c06:	557d                	li	a0,-1
   50c08:	02055d13          	srli	s10,a0,0x20
   50c0c:	a025                	j	50c34 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x81c>
   50c0e:	842a                	mv	s0,a0
_ZN3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE10quick_pushERKS1_():
   50c10:	00446503          	lwu	a0,4(s0)
   50c14:	00150593          	addi	a1,a0,1
   50c18:	c04c                	sw	a1,4(s0)
   50c1a:	008be583          	lwu	a1,8(s7)
   50c1e:	00cbe603          	lwu	a2,12(s7)
   50c22:	050e                	slli	a0,a0,0x3
_ZN3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE7addressEv():
   50c24:	9522                	add	a0,a0,s0
_ZN3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE10quick_pushERKS1_():
   50c26:	c50c                	sw	a1,8(a0)
   50c28:	c550                	sw	a2,12(a0)
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   50c2a:	004a6503          	lwu	a0,4(s4)
   50c2e:	0485                	addi	s1,s1,1
   50c30:	14a4f663          	bgeu	s1,a0,50d7c <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x964>
_ZNK3vecIN12_GLOBAL__N_19line_spanE7va_heap6vl_ptrE6lengthEv():
   50c34:	0889b403          	ld	s0,136(s3)
   50c38:	856a                	mv	a0,s10
   50c3a:	c409                	beqz	s0,50c44 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x82c>
_ZNK3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE6lengthEv():
   50c3c:	4048                	lw	a0,4(s0)
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   50c3e:	157d                	addi	a0,a0,-1
   50c40:	1502                	slli	a0,a0,0x20
   50c42:	9101                	srli	a0,a0,0x20
   50c44:	050e                	slli	a0,a0,0x3
   50c46:	00349b93          	slli	s7,s1,0x3
_ZN3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE7addressEv():
   50c4a:	9522                	add	a0,a0,s0
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   50c4c:	9bd2                	add	s7,s7,s4
   50c4e:	008ba583          	lw	a1,8(s7)
   50c52:	4510                	lw	a2,8(a0)
   50c54:	3ac5ee63          	bltu	a1,a2,51010 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0xbf8>
   50c58:	0009b603          	ld	a2,0(s3)
   50c5c:	00d64683          	lbu	a3,13(a2)
   50c60:	00c56603          	lwu	a2,12(a0)
   50c64:	1582                	slli	a1,a1,0x20
   50c66:	9181                	srli	a1,a1,0x20
   50c68:	96b2                	add	a3,a3,a2
   50c6a:	0685                	addi	a3,a3,1
   50c6c:	02b6f863          	bgeu	a3,a1,50c9c <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x884>
_ZNK3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE5spaceEj():
   50c70:	00042c83          	lw	s9,0(s0)
   50c74:	404c                	lw	a1,4(s0)
   50c76:	016cf533          	and	a0,s9,s6
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   50c7a:	f8b51be3          	bne	a0,a1,50c10 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x7f8>
   50c7e:	020cc663          	bltz	s9,50caa <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x892>
   50c82:	0015059b          	addiw	a1,a0,1
   50c86:	a2ceb0ef          	jal	3beb2 <_ZN10vec_prefix22calculate_allocation_1Ejj>
   50c8a:	0889b583          	ld	a1,136(s3)
   50c8e:	892a                	mv	s2,a0
   50c90:	c985                	beqz	a1,50cc0 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x8a8>
   50c92:	852e                	mv	a0,a1
_ZNK3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE6lengthEv():
   50c94:	0045aa83          	lw	s5,4(a1)
   50c98:	4d81                	li	s11,0
   50c9a:	a035                	j	50cc6 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x8ae>
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   50c9c:	00cba583          	lw	a1,12(s7)
   50ca0:	2601                	sext.w	a2,a2
   50ca2:	f8b674e3          	bgeu	a2,a1,50c2a <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x812>
   50ca6:	c54c                	sw	a1,12(a0)
   50ca8:	b749                	j	50c2a <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x812>
   50caa:	0809b423          	sd	zero,136(s3)
_ZNK3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE6lengthEv():
   50cae:	00442d83          	lw	s11,4(s0)
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   50cb2:	001d891b          	addiw	s2,s11,1
   50cb6:	4511                	li	a0,4
   50cb8:	01256563          	bltu	a0,s2,50cc2 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x8aa>
   50cbc:	4911                	li	s2,4
   50cbe:	a011                	j	50cc2 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x8aa>
   50cc0:	4d81                	li	s11,0
   50cc2:	4501                	li	a0,0
   50cc4:	4a81                	li	s5,0
_ZN3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE13embedded_sizeEj():
   50cc6:	02091593          	slli	a1,s2,0x20
   50cca:	81f5                	srli	a1,a1,0x1d
   50ccc:	05a1                	addi	a1,a1,8
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   50cce:	669500ef          	jal	a1b36 <xrealloc>
   50cd2:	08a9b423          	sd	a0,136(s3)
_ZN3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE13embedded_initEjjj():
   50cd6:	016975b3          	and	a1,s2,s6
   50cda:	c10c                	sw	a1,0(a0)
   50cdc:	01552223          	sw	s5,4(a0)
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   50ce0:	0889b503          	ld	a0,136(s3)
   50ce4:	f20cd5e3          	bgez	s9,50c0e <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x7f6>
   50ce8:	040d8763          	beqz	s11,50d36 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x91e>
   50cec:	45a1                	li	a1,8
   50cee:	68e2                	ld	a7,24(sp)
   50cf0:	8646                	mv	a2,a7
   50cf2:	0115e363          	bltu	a1,a7,50cf8 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x8e0>
   50cf6:	4621                	li	a2,8
   50cf8:	020d9593          	slli	a1,s11,0x20
   50cfc:	9181                	srli	a1,a1,0x20
   50cfe:	00c5e663          	bltu	a1,a2,50d0a <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x8f2>
   50d02:	40850633          	sub	a2,a0,s0
   50d06:	03867d63          	bgeu	a2,s8,50d40 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x928>
   50d0a:	866e                	mv	a2,s11
   50d0c:	86a2                	mv	a3,s0
   50d0e:	00868593          	addi	a1,a3,8
   50d12:	0521                	addi	a0,a0,8
   50d14:	167d                	addi	a2,a2,-1
   50d16:	1602                	slli	a2,a2,0x20
   50d18:	8275                	srli	a2,a2,0x1d
   50d1a:	9636                	add	a2,a2,a3
   50d1c:	0641                	addi	a2,a2,16
   50d1e:	0005e683          	lwu	a3,0(a1)
   50d22:	0045e703          	lwu	a4,4(a1)
   50d26:	05a1                	addi	a1,a1,8
   50d28:	c114                	sw	a3,0(a0)
   50d2a:	c158                	sw	a4,4(a0)
   50d2c:	0521                	addi	a0,a0,8
   50d2e:	fec598e3          	bne	a1,a2,50d1e <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x906>
   50d32:	0889b503          	ld	a0,136(s3)
   50d36:	01b52223          	sw	s11,4(a0)
   50d3a:	0889b403          	ld	s0,136(s3)
   50d3e:	bdc9                	j	50c10 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x7f8>
   50d40:	7622                	ld	a2,40(sp)
   50d42:	820d                	srli	a2,a2,0x3
   50d44:	00850793          	addi	a5,a0,8
   50d48:	66c2                	ld	a3,16(sp)
   50d4a:	02d60633          	mul	a2,a2,a3
   50d4e:	00b67833          	and	a6,a2,a1
   50d52:	410d863b          	subw	a2,s11,a6
   50d56:	00381713          	slli	a4,a6,0x3
   50d5a:	00e406b3          	add	a3,s0,a4
   50d5e:	953a                	add	a0,a0,a4
   50d60:	0421                	addi	s0,s0,8
   50d62:	8742                	mv	a4,a6
   50d64:	22840407          	vl2r.v	v8,(s0)
   50d68:	41170733          	sub	a4,a4,a7
   50d6c:	22878427          	vs2r.v	v8,(a5)
   50d70:	97e2                	add	a5,a5,s8
   50d72:	9462                	add	s0,s0,s8
   50d74:	fb65                	bnez	a4,50d64 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x94c>
   50d76:	f8b81ce3          	bne	a6,a1,50d0e <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x8f6>
   50d7a:	bf65                	j	50d32 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x91a>
_ZNK3vecIN12_GLOBAL__N_19line_spanE7va_heap6vl_ptrE6lengthEv():
   50d7c:	0889b583          	ld	a1,136(s3)
   50d80:	6aa2                	ld	s5,8(sp)
   50d82:	30058f63          	beqz	a1,510a0 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0xc88>
_ZNK3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE6lengthEv():
   50d86:	41c8                	lw	a0,4(a1)
   50d88:	4605                	li	a2,1
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   50d8a:	02c50b63          	beq	a0,a2,50dc0 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x9a8>
   50d8e:	30050963          	beqz	a0,510a0 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0xc88>
   50d92:	1502                	slli	a0,a0,0x20
   50d94:	4594                	lw	a3,8(a1)
   50d96:	45d0                	lw	a2,12(a1)
   50d98:	9101                	srli	a0,a0,0x20
   50d9a:	157d                	addi	a0,a0,-1
   50d9c:	05d1                	addi	a1,a1,20
   50d9e:	28d66563          	bltu	a2,a3,51028 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0xc10>
   50da2:	ffc5a703          	lw	a4,-4(a1)
   50da6:	419c                	lw	a5,0(a1)
   50da8:	28e7ec63          	bltu	a5,a4,51040 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0xc28>
   50dac:	2ce6f263          	bgeu	a3,a4,51070 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0xc58>
   50db0:	2605                	addiw	a2,a2,1
   50db2:	2ae67363          	bgeu	a2,a4,51058 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0xc40>
   50db6:	157d                	addi	a0,a0,-1
   50db8:	05a1                	addi	a1,a1,8
   50dba:	863e                	mv	a2,a5
   50dbc:	86ba                	mv	a3,a4
   50dbe:	f165                	bnez	a0,50d9e <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x986>
_ZNK3vecIN12_GLOBAL__N_19line_spanE7va_heap6vl_ptrE18using_auto_storageEv():
   50dc0:	000a2503          	lw	a0,0(s4)
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   50dc4:	00054963          	bltz	a0,50dd6 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x9be>
_ZN7va_heap7releaseIN12_GLOBAL__N_19line_spanEEEvRP3vecIT_S_8vl_embedE():
   50dc8:	8552                	mv	a0,s4
   50dca:	e96c30ef          	jal	14460 <free@plt>
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   50dce:	0889b503          	ld	a0,136(s3)
   50dd2:	e901                	bnez	a0,50de2 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x9ca>
   50dd4:	ac55                	j	51088 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0xc70>
_ZN3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE8truncateEj():
   50dd6:	000a2223          	sw	zero,4(s4)
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   50dda:	0889b503          	ld	a0,136(s3)
   50dde:	2a050563          	beqz	a0,51088 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0xc70>
_ZNK3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE6lengthEv():
   50de2:	414c                	lw	a1,4(a0)
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   50de4:	2a058263          	beqz	a1,51088 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0xc70>
   50de8:	15fd                	addi	a1,a1,-1
   50dea:	1582                	slli	a1,a1,0x20
   50dec:	81f5                	srli	a1,a1,0x1d
   50dee:	952e                	add	a0,a0,a1
   50df0:	4548                	lw	a0,12(a0)
   50df2:	00a025b3          	sgtz	a1,a0
   50df6:	40b005b3          	neg	a1,a1
   50dfa:	8d6d                	and	a0,a0,a1
   50dfc:	c12f00ef          	jal	4120e <_Z10num_digitsi>
   50e00:	0889b583          	ld	a1,136(s3)
   50e04:	08a9a823          	sw	a0,144(s3)
   50e08:	c999                	beqz	a1,50e1e <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0xa06>
_ZNK3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE6lengthEv():
   50e0a:	41cc                	lw	a1,4(a1)
   50e0c:	4609                	li	a2,2
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   50e0e:	00c5e863          	bltu	a1,a2,50e1e <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0xa06>
   50e12:	458d                	li	a1,3
   50e14:	00a5c363          	blt	a1,a0,50e1a <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0xa02>
   50e18:	450d                	li	a0,3
   50e1a:	08a9a823          	sw	a0,144(s3)
   50e1e:	0009b583          	ld	a1,0(s3)
   50e22:	4990                	lw	a2,16(a1)
   50e24:	00c55463          	bge	a0,a2,50e2c <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0xa14>
   50e28:	fff60513          	addi	a0,a2,-1
   50e2c:	08a9a823          	sw	a0,144(s3)
   50e30:	0809aa23          	sw	zero,148(s3)
   50e34:	0045aa03          	lw	s4,4(a1)
   50e38:	0e0a0663          	beqz	s4,50f24 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0xb0c>
   50e3c:	0109b503          	ld	a0,16(s3)
   50e40:	0509b583          	ld	a1,80(s3)
   50e44:	0589a603          	lw	a2,88(s3)
   50e48:	4e90c0ef          	jal	5db30 <_ZN10file_cache15get_source_lineEPKci>
   50e4c:	cd61                	beqz	a0,50f24 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0xb0c>
   50e4e:	88ae                	mv	a7,a1
   50e50:	0709a903          	lw	s2,112(s3)
   50e54:	2581                	sext.w	a1,a1
   50e56:	04b05563          	blez	a1,50ea0 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0xa88>
   50e5a:	7582                	ld	a1,32(sp)
   50e5c:	0585                	addi	a1,a1,1
   50e5e:	02189713          	slli	a4,a7,0x21
   50e62:	02000693          	li	a3,32
   50e66:	008007b7          	lui	a5,0x800
   50e6a:	00b8f833          	and	a6,a7,a1
   50e6e:	02175593          	srli	a1,a4,0x21
   50e72:	07c5                	addi	a5,a5,17 # 800011 <__BSS_END__+0x6582b1>
   50e74:	07a6                	slli	a5,a5,0x9
   50e76:	4705                	li	a4,1
   50e78:	8442                	mv	s0,a6
   50e7a:	8622                	mv	a2,s0
   50e7c:	008504b3          	add	s1,a0,s0
   50e80:	fff4c403          	lbu	s0,-1(s1)
   50e84:	0c86e463          	bltu	a3,s0,50f4c <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0xb34>
   50e88:	0087d4b3          	srl	s1,a5,s0
   50e8c:	8885                	andi	s1,s1,1
   50e8e:	ccdd                	beqz	s1,50f4c <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0xb34>
   50e90:	fff60413          	addi	s0,a2,-1
   50e94:	35fd                	addiw	a1,a1,-1
   50e96:	fec742e3          	blt	a4,a2,50e7a <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0xa62>
   50e9a:	010035b3          	snez	a1,a6
   50e9e:	15fd                	addi	a1,a1,-1
   50ea0:	2605c063          	bltz	a1,51100 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0xce8>
   50ea4:	2881                	sext.w	a7,a7
   50ea6:	24b8c163          	blt	a7,a1,510e8 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0xcd0>
   50eaa:	4581                	li	a1,0
_Z17cpp_display_widthPKciRK22cpp_char_column_policy():
   50eac:	862e                	mv	a2,a1
   50eae:	86d6                	mv	a3,s5
   50eb0:	70a160ef          	jal	675ba <_Z33cpp_byte_column_to_display_columnPKciiRK22cpp_char_column_policy>
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   50eb4:	06090863          	beqz	s2,50f24 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0xb0c>
   50eb8:	07254663          	blt	a0,s2,50f24 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0xb0c>
   50ebc:	0009b583          	ld	a1,0(s3)
   50ec0:	00d5c583          	lbu	a1,13(a1)
   50ec4:	e18d                	bnez	a1,50ee6 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0xace>
   50ec6:	4585                	li	a1,1
   50ec8:	00a5863b          	addw	a2,a1,a0
   50ecc:	02ca4463          	blt	s4,a2,50ef4 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0xadc>
   50ed0:	a891                	j	50f24 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0xb0c>
   50ed2:	0809b423          	sd	zero,136(s3)
_ZNK3vecIN12_GLOBAL__N_19line_spanE7va_heap8vl_embedE6lengthEv():
   50ed6:	0044a903          	lw	s2,4(s1)
_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info():
   50eda:	0019041b          	addiw	s0,s2,1
   50ede:	4511                	li	a0,4
   50ee0:	c68578e3          	bgeu	a0,s0,50b50 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x738>
   50ee4:	b1bd                	j	50b52 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x73a>
   50ee6:	0909a583          	lw	a1,144(s3)
   50eea:	058d                	addi	a1,a1,3
   50eec:	00a5863b          	addw	a2,a1,a0
   50ef0:	02ca5a63          	bge	s4,a2,50f24 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0xb0c>
   50ef4:	4125063b          	subw	a2,a0,s2
   50ef8:	46a9                	li	a3,10
   50efa:	00d64363          	blt	a2,a3,50f00 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0xae8>
   50efe:	4629                	li	a2,10
   50f00:	00c586bb          	addw	a3,a1,a2
   50f04:	0346d063          	bge	a3,s4,50f24 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0xb0c>
   50f08:	012585bb          	addw	a1,a1,s2
   50f0c:	40ca063b          	subw	a2,s4,a2
   50f10:	00b65a63          	bge	a2,a1,50f24 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0xb0c>
   50f14:	8d91                	sub	a1,a1,a2
   50f16:	9d0d                	subw	a0,a0,a1
   50f18:	00252513          	slti	a0,a0,2
   50f1c:	157d                	addi	a0,a0,-1
   50f1e:	8d6d                	and	a0,a0,a1
   50f20:	08a9aa23          	sw	a0,148(s3)
   50f24:	70ee                	ld	ra,248(sp)
   50f26:	744e                	ld	s0,240(sp)
   50f28:	74ae                	ld	s1,232(sp)
   50f2a:	790e                	ld	s2,224(sp)
   50f2c:	69ee                	ld	s3,216(sp)
   50f2e:	6a4e                	ld	s4,208(sp)
   50f30:	6aae                	ld	s5,200(sp)
   50f32:	6b0e                	ld	s6,192(sp)
   50f34:	7bea                	ld	s7,184(sp)
   50f36:	7c4a                	ld	s8,176(sp)
   50f38:	7caa                	ld	s9,168(sp)
   50f3a:	7d0a                	ld	s10,160(sp)
   50f3c:	6dea                	ld	s11,152(sp)
   50f3e:	6111                	addi	sp,sp,256
   50f40:	8082                	ret
   50f42:	4901                	li	s2,0
   50f44:	4b81                	li	s7,0
   50f46:	4501                	li	a0,0
   50f48:	4a81                	li	s5,0
   50f4a:	b901                	j	50b5a <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x742>
   50f4c:	2881                	sext.w	a7,a7
   50f4e:	18b8cd63          	blt	a7,a1,510e8 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0xcd0>
   50f52:	66c2                	ld	a3,16(sp)
   50f54:	0685                	addi	a3,a3,1
   50f56:	8e75                	and	a2,a2,a3
   50f58:	962a                	add	a2,a2,a0
   50f5a:	fff64603          	lbu	a2,-1(a2)
   50f5e:	02000693          	li	a3,32
   50f62:	f4c6e5e3          	bltu	a3,a2,50eac <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0xa94>
   50f66:	008006b7          	lui	a3,0x800
   50f6a:	06c5                	addi	a3,a3,17 # 800011 <__BSS_END__+0x6582b1>
   50f6c:	06a6                	slli	a3,a3,0x9
   50f6e:	00c6d633          	srl	a2,a3,a2
   50f72:	8a05                	andi	a2,a2,1
   50f74:	de05                	beqz	a2,50eac <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0xa94>
   50f76:	000e5537          	lui	a0,0xe5
   50f7a:	91c50513          	addi	a0,a0,-1764 # e491c <_ZZ13trim_filenamePKcE9this_file+0x1402>
   50f7e:	000e5637          	lui	a2,0xe5
   50f82:	9c660613          	addi	a2,a2,-1594 # e49c6 <_ZZ13trim_filenamePKcE9this_file+0x14ac>
   50f86:	41500593          	li	a1,1045
   50f8a:	f5eee0ef          	jal	3f6e8 <_Z11fancy_abortPKciS0_>
   50f8e:	76a2                	ld	a3,40(sp)
   50f90:	828d                	srli	a3,a3,0x3
   50f92:	00860413          	addi	s0,a2,8
   50f96:	6742                	ld	a4,16(sp)
   50f98:	02e686b3          	mul	a3,a3,a4
   50f9c:	00a6f833          	and	a6,a3,a0
   50fa0:	410906bb          	subw	a3,s2,a6
   50fa4:	00381793          	slli	a5,a6,0x3
   50fa8:	00f48733          	add	a4,s1,a5
   50fac:	963e                	add	a2,a2,a5
   50fae:	04a1                	addi	s1,s1,8
   50fb0:	87c2                	mv	a5,a6
   50fb2:	22848407          	vl2r.v	v8,(s1)
   50fb6:	8f8d                	sub	a5,a5,a1
   50fb8:	22840427          	vs2r.v	v8,(s0)
   50fbc:	9462                	add	s0,s0,s8
   50fbe:	94e2                	add	s1,s1,s8
   50fc0:	fbed                	bnez	a5,50fb2 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0xb9a>
   50fc2:	bea811e3          	bne	a6,a0,50ba4 <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x78c>
   50fc6:	b111                	j	50bca <_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info+0x7b2>
   50fc8:	000e5537          	lui	a0,0xe5
   50fcc:	91c50513          	addi	a0,a0,-1764 # e491c <_ZZ13trim_filenamePKcE9this_file+0x1402>
   50fd0:	000e5637          	lui	a2,0xe5
   50fd4:	98f60613          	addi	a2,a2,-1649 # e498f <_ZZ13trim_filenamePKcE9this_file+0x1475>
   50fd8:	69e00593          	li	a1,1694
   50fdc:	f0cee0ef          	jal	3f6e8 <_Z11fancy_abortPKciS0_>
   50fe0:	000e5537          	lui	a0,0xe5
   50fe4:	91c50513          	addi	a0,a0,-1764 # e491c <_ZZ13trim_filenamePKcE9this_file+0x1402>
   50fe8:	000e5637          	lui	a2,0xe5
   50fec:	98f60613          	addi	a2,a2,-1649 # e498f <_ZZ13trim_filenamePKcE9this_file+0x1475>
   50ff0:	6a700593          	li	a1,1703
   50ff4:	ef4ee0ef          	jal	3f6e8 <_Z11fancy_abortPKciS0_>
   50ff8:	000e5537          	lui	a0,0xe5
   50ffc:	91c50513          	addi	a0,a0,-1764 # e491c <_ZZ13trim_filenamePKcE9this_file+0x1402>
   51000:	000e5637          	lui	a2,0xe5
   51004:	9a460613          	addi	a2,a2,-1628 # e49a4 <_ZZ13trim_filenamePKcE9this_file+0x148a>
   51008:	12a00593          	li	a1,298
   5100c:	edcee0ef          	jal	3f6e8 <_Z11fancy_abortPKciS0_>
   51010:	000e5537          	lui	a0,0xe5
   51014:	91c50513          	addi	a0,a0,-1764 # e491c <_ZZ13trim_filenamePKcE9this_file+0x1402>
   51018:	000e5637          	lui	a2,0xe5
   5101c:	98f60613          	addi	a2,a2,-1649 # e498f <_ZZ13trim_filenamePKcE9this_file+0x1475>
   51020:	6b600593          	li	a1,1718
   51024:	ec4ee0ef          	jal	3f6e8 <_Z11fancy_abortPKciS0_>
   51028:	000e5537          	lui	a0,0xe5
   5102c:	91c50513          	addi	a0,a0,-1764 # e491c <_ZZ13trim_filenamePKcE9this_file+0x1402>
   51030:	000e5637          	lui	a2,0xe5
   51034:	98f60613          	addi	a2,a2,-1649 # e498f <_ZZ13trim_filenamePKcE9this_file+0x1475>
   51038:	6cd00593          	li	a1,1741
   5103c:	eacee0ef          	jal	3f6e8 <_Z11fancy_abortPKciS0_>
   51040:	000e5537          	lui	a0,0xe5
   51044:	91c50513          	addi	a0,a0,-1764 # e491c <_ZZ13trim_filenamePKcE9this_file+0x1402>
   51048:	000e5637          	lui	a2,0xe5
   5104c:	98f60613          	addi	a2,a2,-1649 # e498f <_ZZ13trim_filenamePKcE9this_file+0x1475>
   51050:	6ce00593          	li	a1,1742
   51054:	e94ee0ef          	jal	3f6e8 <_Z11fancy_abortPKciS0_>
   51058:	000e5537          	lui	a0,0xe5
   5105c:	91c50513          	addi	a0,a0,-1764 # e491c <_ZZ13trim_filenamePKcE9this_file+0x1402>
   51060:	000e5637          	lui	a2,0xe5
   51064:	98f60613          	addi	a2,a2,-1649 # e498f <_ZZ13trim_filenamePKcE9this_file+0x1475>
   51068:	6d200593          	li	a1,1746
   5106c:	e7cee0ef          	jal	3f6e8 <_Z11fancy_abortPKciS0_>
   51070:	000e5537          	lui	a0,0xe5
   51074:	91c50513          	addi	a0,a0,-1764 # e491c <_ZZ13trim_filenamePKcE9this_file+0x1402>
   51078:	000e5637          	lui	a2,0xe5
   5107c:	98f60613          	addi	a2,a2,-1649 # e498f <_ZZ13trim_filenamePKcE9this_file+0x1475>
   51080:	6d000593          	li	a1,1744
   51084:	e64ee0ef          	jal	3f6e8 <_Z11fancy_abortPKciS0_>
   51088:	000e5537          	lui	a0,0xe5
   5108c:	91c50513          	addi	a0,a0,-1764 # e491c <_ZZ13trim_filenamePKcE9this_file+0x1402>
   51090:	000e5637          	lui	a2,0xe5
   51094:	9ae60613          	addi	a2,a2,-1618 # e49ae <_ZZ13trim_filenamePKcE9this_file+0x1494>
   51098:	6dd00593          	li	a1,1757
   5109c:	e4cee0ef          	jal	3f6e8 <_Z11fancy_abortPKciS0_>
   510a0:	000e5537          	lui	a0,0xe5
   510a4:	91c50513          	addi	a0,a0,-1764 # e491c <_ZZ13trim_filenamePKcE9this_file+0x1402>
   510a8:	000e5637          	lui	a2,0xe5
   510ac:	98f60613          	addi	a2,a2,-1649 # e498f <_ZZ13trim_filenamePKcE9this_file+0x1475>
   510b0:	6c700593          	li	a1,1735
   510b4:	e34ee0ef          	jal	3f6e8 <_Z11fancy_abortPKciS0_>
   510b8:	000e5537          	lui	a0,0xe5
   510bc:	91c50513          	addi	a0,a0,-1764 # e491c <_ZZ13trim_filenamePKcE9this_file+0x1402>
   510c0:	000e5637          	lui	a2,0xe5
   510c4:	98f60613          	addi	a2,a2,-1649 # e498f <_ZZ13trim_filenamePKcE9this_file+0x1475>
   510c8:	6b000593          	li	a1,1712
   510cc:	e1cee0ef          	jal	3f6e8 <_Z11fancy_abortPKciS0_>
   510d0:	000e5537          	lui	a0,0xe5
   510d4:	91c50513          	addi	a0,a0,-1764 # e491c <_ZZ13trim_filenamePKcE9this_file+0x1402>
   510d8:	000e5637          	lui	a2,0xe5
   510dc:	98f60613          	addi	a2,a2,-1649 # e498f <_ZZ13trim_filenamePKcE9this_file+0x1475>
   510e0:	69500593          	li	a1,1685
   510e4:	e04ee0ef          	jal	3f6e8 <_Z11fancy_abortPKciS0_>
   510e8:	000e5537          	lui	a0,0xe5
   510ec:	91c50513          	addi	a0,a0,-1764 # e491c <_ZZ13trim_filenamePKcE9this_file+0x1402>
   510f0:	000e5637          	lui	a2,0xe5
   510f4:	9c660613          	addi	a2,a2,-1594 # e49c6 <_ZZ13trim_filenamePKcE9this_file+0x14ac>
   510f8:	41100593          	li	a1,1041
   510fc:	decee0ef          	jal	3f6e8 <_Z11fancy_abortPKciS0_>
   51100:	000e5537          	lui	a0,0xe5
   51104:	91c50513          	addi	a0,a0,-1764 # e491c <_ZZ13trim_filenamePKcE9this_file+0x1402>
   51108:	000e5637          	lui	a2,0xe5
   5110c:	9c660613          	addi	a2,a2,-1594 # e49c6 <_ZZ13trim_filenamePKcE9this_file+0x14ac>
   51110:	41000593          	li	a1,1040
   51114:	dd4ee0ef          	jal	3f6e8 <_Z11fancy_abortPKciS0_>
   51118:	000e5537          	lui	a0,0xe5
   5111c:	91c50513          	addi	a0,a0,-1764 # e491c <_ZZ13trim_filenamePKcE9this_file+0x1402>
   51120:	000e5637          	lui	a2,0xe5
   51124:	96e60613          	addi	a2,a2,-1682 # e496e <_ZZ13trim_filenamePKcE9this_file+0x1454>
   51128:	52700593          	li	a1,1319
   5112c:	dbcee0ef          	jal	3f6e8 <_Z11fancy_abortPKciS0_>
000000000008bb30 <elf_open_debugfile_by_buildid>:
elf_open_debugfile_by_buildid():
   8bb30:	715d                	addi	sp,sp,-80
   8bb32:	e486                	sd	ra,72(sp)
   8bb34:	e0a2                	sd	s0,64(sp)
   8bb36:	fc26                	sd	s1,56(sp)
   8bb38:	f84a                	sd	s2,48(sp)
   8bb3a:	f44e                	sd	s3,40(sp)
   8bb3c:	f052                	sd	s4,32(sp)
   8bb3e:	ec56                	sd	s5,24(sp)
   8bb40:	e85a                	sd	s6,16(sp)
   8bb42:	e45e                	sd	s7,8(sp)
   8bb44:	8aba                	mv	s5,a4
   8bb46:	8b36                	mv	s6,a3
   8bb48:	8432                	mv	s0,a2
   8bb4a:	8a2e                	mv	s4,a1
   8bb4c:	89aa                	mv	s3,a0
   8bb4e:	00161b93          	slli	s7,a2,0x1
   8bb52:	021b8913          	addi	s2,s7,33
   8bb56:	85ca                	mv	a1,s2
   8bb58:	8636                	mv	a2,a3
   8bb5a:	86ba                	mv	a3,a4
   8bb5c:	9b9f90ef          	jal	85514 <backtrace_alloc>
   8bb60:	cd15                	beqz	a0,8bb9c <elf_open_debugfile_by_buildid+0x6c>
   8bb62:	0005f597          	auipc	a1,0x5f
   8bb66:	c2158593          	addi	a1,a1,-991 # ea783 <_ZZL13pch_open_fileP10cpp_readerP9_cpp_filePbE9extension+0x2368>
   8bb6a:	cc087057          	vsetivli	zero,16,e8,m1,ta,ma
   8bb6e:	02058407          	vle8.v	v8,(a1)
   8bb72:	05a5                	addi	a1,a1,9
   8bb74:	02058487          	vle8.v	v9,(a1)
   8bb78:	02050427          	vse8.v	v8,(a0)
   8bb7c:	00950593          	addi	a1,a0,9
   8bb80:	020584a7          	vse8.v	v9,(a1)
   8bb84:	cc11                	beqz	s0,8bba0 <elf_open_debugfile_by_buildid+0x70>
   8bb86:	000a4583          	lbu	a1,0(s4)
   8bb8a:	0a000693          	li	a3,160
   8bb8e:	0045d613          	srli	a2,a1,0x4
   8bb92:	00d5ea63          	bltu	a1,a3,8bba6 <elf_open_debugfile_by_buildid+0x76>
   8bb96:	05760613          	addi	a2,a2,87
   8bb9a:	a801                	j	8bbaa <elf_open_debugfile_by_buildid+0x7a>
   8bb9c:	547d                	li	s0,-1
   8bb9e:	a28d                	j	8bd00 <elf_open_debugfile_by_buildid+0x1d0>
   8bba0:	01950593          	addi	a1,a0,25
   8bba4:	a231                	j	8bcb0 <elf_open_debugfile_by_buildid+0x180>
   8bba6:	03060613          	addi	a2,a2,48
   8bbaa:	89bd                	andi	a1,a1,15
   8bbac:	46a9                	li	a3,10
   8bbae:	00c50ca3          	sb	a2,25(a0)
   8bbb2:	00d5e563          	bltu	a1,a3,8bbbc <elf_open_debugfile_by_buildid+0x8c>
   8bbb6:	05758593          	addi	a1,a1,87
   8bbba:	a019                	j	8bbc0 <elf_open_debugfile_by_buildid+0x90>
   8bbbc:	03058593          	addi	a1,a1,48
   8bbc0:	01c50613          	addi	a2,a0,28
   8bbc4:	02f00693          	li	a3,47
   8bbc8:	fff40293          	addi	t0,s0,-1
   8bbcc:	00b50d23          	sb	a1,26(a0)
   8bbd0:	00d50da3          	sb	a3,27(a0)
   8bbd4:	00028b63          	beqz	t0,8bbea <elf_open_debugfile_by_buildid+0xba>
   8bbd8:	c2202773          	csrr	a4,vlenb
   8bbdc:	00171393          	slli	t2,a4,0x1
   8bbe0:	0072f763          	bgeu	t0,t2,8bbee <elf_open_debugfile_by_buildid+0xbe>
   8bbe4:	4885                	li	a7,1
   8bbe6:	85b2                	mv	a1,a2
   8bbe8:	a8ad                	j	8bc62 <elf_open_debugfile_by_buildid+0x132>
   8bbea:	85b2                	mv	a1,a2
   8bbec:	a0d1                	j	8bcb0 <elf_open_debugfile_by_buildid+0x180>
   8bbee:	407005b3          	neg	a1,t2
   8bbf2:	00b2f833          	and	a6,t0,a1
   8bbf6:	407805b3          	sub	a1,a6,t2
   8bbfa:	0275d7b3          	divu	a5,a1,t2
   8bbfe:	00375493          	srli	s1,a4,0x3
   8bc02:	00271e13          	slli	t3,a4,0x2
   8bc06:	001a0693          	addi	a3,s4,1
   8bc0a:	fa000313          	li	t1,-96
   8bc0e:	03000413          	li	s0,48
   8bc12:	00181593          	slli	a1,a6,0x1
   8bc16:	00180893          	addi	a7,a6,1
   8bc1a:	95b2                	add	a1,a1,a2
   8bc1c:	0792                	slli	a5,a5,0x4
   8bc1e:	07c1                	addi	a5,a5,16
   8bc20:	029784b3          	mul	s1,a5,s1
   8bc24:	94b6                	add	s1,s1,a3
   8bc26:	05700793          	li	a5,87
   8bc2a:	22868407          	vl2r.v	v8,(a3)
   8bc2e:	969e                	add	a3,a3,t2
   8bc30:	04107757          	vsetvli	a4,zero,e8,m2,ta,mu
   8bc34:	a2823557          	vsrl.vi	v10,v8,4
   8bc38:	6a834057          	vmsltu.vx	v0,v8,t1
   8bc3c:	2687b457          	vand.vi	v8,v8,15
   8bc40:	02a7c657          	vadd.vx	v12,v10,a5
   8bc44:	28a44657          	vor.vx	v12,v10,s0,v0.t
   8bc48:	7284b057          	vmsleu.vi	v0,v8,9
   8bc4c:	0287c757          	vadd.vx	v14,v8,a5
   8bc50:	28844757          	vor.vx	v14,v8,s0,v0.t
   8bc54:	22060627          	vsseg2e8.v	v12,(a2)
   8bc58:	9672                	add	a2,a2,t3
   8bc5a:	fc9698e3          	bne	a3,s1,8bc2a <elf_open_debugfile_by_buildid+0xfa>
   8bc5e:	05028963          	beq	t0,a6,8bcb0 <elf_open_debugfile_by_buildid+0x180>
   8bc62:	9a46                	add	s4,s4,a7
   8bc64:	0886                	slli	a7,a7,0x1
   8bc66:	0a000613          	li	a2,160
   8bc6a:	411b86b3          	sub	a3,s7,a7
   8bc6e:	96ae                	add	a3,a3,a1
   8bc70:	4729                	li	a4,10
   8bc72:	a819                	j	8bc88 <elf_open_debugfile_by_buildid+0x158>
   8bc74:	05778493          	addi	s1,a5,87
   8bc78:	00258793          	addi	a5,a1,2
   8bc7c:	009580a3          	sb	s1,1(a1)
   8bc80:	0a05                	addi	s4,s4,1
   8bc82:	85be                	mv	a1,a5
   8bc84:	02d78563          	beq	a5,a3,8bcae <elf_open_debugfile_by_buildid+0x17e>
   8bc88:	000a4783          	lbu	a5,0(s4)
   8bc8c:	0047d493          	srli	s1,a5,0x4
   8bc90:	00c7e563          	bltu	a5,a2,8bc9a <elf_open_debugfile_by_buildid+0x16a>
   8bc94:	05748493          	addi	s1,s1,87
   8bc98:	a019                	j	8bc9e <elf_open_debugfile_by_buildid+0x16e>
   8bc9a:	03048493          	addi	s1,s1,48
   8bc9e:	8bbd                	andi	a5,a5,15
   8bca0:	00958023          	sb	s1,0(a1)
   8bca4:	fce7f8e3          	bgeu	a5,a4,8bc74 <elf_open_debugfile_by_buildid+0x144>
   8bca8:	03078493          	addi	s1,a5,48
   8bcac:	b7f1                	j	8bc78 <elf_open_debugfile_by_buildid+0x148>
   8bcae:	85be                	mv	a1,a5
   8bcb0:	06700613          	li	a2,103
   8bcb4:	06200693          	li	a3,98
   8bcb8:	06500713          	li	a4,101
   8bcbc:	06400793          	li	a5,100
   8bcc0:	02e00493          	li	s1,46
   8bcc4:	00958023          	sb	s1,0(a1)
   8bcc8:	00f580a3          	sb	a5,1(a1)
   8bccc:	00e58123          	sb	a4,2(a1)
   8bcd0:	00d581a3          	sb	a3,3(a1)
   8bcd4:	07500693          	li	a3,117
   8bcd8:	00d58223          	sb	a3,4(a1)
   8bcdc:	00c582a3          	sb	a2,5(a1)
   8bce0:	00058323          	sb	zero,6(a1)
   8bce4:	0054                	addi	a3,sp,4
   8bce6:	84aa                	mv	s1,a0
   8bce8:	85da                	mv	a1,s6
   8bcea:	8656                	mv	a2,s5
   8bcec:	d13f90ef          	jal	859fe <backtrace_open>
   8bcf0:	842a                	mv	s0,a0
   8bcf2:	854e                	mv	a0,s3
   8bcf4:	85a6                	mv	a1,s1
   8bcf6:	864a                	mv	a2,s2
   8bcf8:	86da                	mv	a3,s6
   8bcfa:	8756                	mv	a4,s5
   8bcfc:	93bf90ef          	jal	85636 <backtrace_free>
   8bd00:	8522                	mv	a0,s0
   8bd02:	60a6                	ld	ra,72(sp)
   8bd04:	6406                	ld	s0,64(sp)
   8bd06:	74e2                	ld	s1,56(sp)
   8bd08:	7942                	ld	s2,48(sp)
   8bd0a:	79a2                	ld	s3,40(sp)
   8bd0c:	7a02                	ld	s4,32(sp)
   8bd0e:	6ae2                	ld	s5,24(sp)
   8bd10:	6b42                	ld	s6,16(sp)
   8bd12:	6ba2                	ld	s7,8(sp)
   8bd14:	6161                	addi	sp,sp,80
   8bd16:	8082                	ret
"""

STUB_CALLEE_DUMP = r"""\
000000000009f000 <_fixture_concat_stub>:
     9f000: 9682                 jalr	a3
     9f002: 8082                 ret
"""


@lru_cache(maxsize=2)
def load_program(*, include_stub_callee: bool = True):
    """Parse the bundled disassembly into a CFG-backed ``Program``."""

    from chimera.preprocess.offline.analysis.arch.riscv.rvv.services import (
        RvvServices,
    )
    from chimera.preprocess.offline.analysis.arch.riscv.services import (
        RiscvServices,
    )
    from chimera.preprocess.offline.analysis.program_model.parser import parse_dump
    from chimera.preprocess.offline.analysis.toolchain.objdump import LinuxObjdump

    text = STACK_FUNCTIONS_DUMP
    if include_stub_callee:
        text = text + STUB_CALLEE_DUMP
    adapter = LinuxObjdump("objdump")
    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory) / "xgcc-gate2.dump"
        source.write_text(text, encoding="utf-8")
        parsed = parse_dump(
            source,
            adapter.parse_format,
            is_external_trampoline=adapter.is_external_trampoline,
            retain_dump_lines=False,
        )
    return RiscvServices(RvvServices()).build_cfg(parsed)


def function(program, name: str):
    """Return the named function of a loaded fixture program."""

    for candidate in program.functions:
        if candidate.name == name:
            return candidate
    raise KeyError(name)



# region Follow-up evidence (origin attribution, 2026-09-20)

#: The same ELF, dumped again for the functions the origin attribution and the
#: size-origin proof are about.  ``_ZL13close_at_filev`` appears in both
#: extracts; the duplicated body is kept because it is the check that the two
#: dumps really are the same binary (see the fixture integrity test).
FOLLOWUP_FUNCTIONS = (
    "cplus_demangle_print_callback",
    "_ZNK6driver12set_up_specsEv",
    "_ZL19destringize_and_runP10cpp_readerPK10cpp_stringm",
)

DEMANGLE_PRINT_CALLBACK = "cplus_demangle_print_callback"
#: The two dynamic allocations of the d_print_info buffer.  Their sizes come
#: from stack slots that ``d_count_templates_scopes`` fills in, so the size
#: origin is a callee summary question.
DEMANGLE_ALLOCATIONS = (0x96D12, 0x96D24)
DEMANGLE_COUNT_CALL = 0x96CDC
DEMANGLE_COUNT_CALLEE = 0x996FE
#: The frame state is released by ``mv sp,s3`` before the callback is called.
DEMANGLE_RELEASE = 0x96D4A
DEMANGLE_CALLBACK_CALL = 0x96D6A

SET_UP_SPECS = "_ZNK6driver12set_up_specsEv"
#: ``sub s4,sp,a0`` / ``mv sp,s1``: the alloca-style adjustment whose size is
#: the result of an external ``strlen@plt`` call.
SET_UP_SPECS_ALLOCATION = 0x16F8E
SET_UP_SPECS_ALLOCA_SITE = 0x16F8A
SET_UP_SPECS_STRLEN_CALL = 0x16F80
SET_UP_SPECS_RELEASE = 0x17D20
SET_UP_SPECS_CALL = 0x17CEC

DESTRINGIZE_AND_RUN = "_ZL19destringize_and_runP10cpp_readerPK10cpp_stringm"
#: The alloca-style adjustment whose size is loaded from the caller's
#: ``cpp_string`` object: ``lwu a0,0(a1)`` at 0x6a9ea.
DESTRINGIZE_ALLOCATION = 0x6AA00
DESTRINGIZE_ALLOA_SITE = 0x6A9FC
DESTRINGIZE_LENGTH_LOAD = 0x6A9EA
DESTRINGIZE_RELEASE = 0x6AC7C
DESTRINGIZE_CALL = 0x6AC3A

FOLLOWUP_FUNCTIONS_DUMP = r"""\
0000000000096c86 <cplus_demangle_print_callback>:
cplus_demangle_print_callback():
   96c86:	7161                	addi	sp,sp,-432
   96c88:	f706                	sd	ra,424(sp)
   96c8a:	f322                	sd	s0,416(sp)
   96c8c:	ef26                	sd	s1,408(sp)
   96c8e:	eb4a                	sd	s2,400(sp)
   96c90:	e74e                	sd	s3,392(sp)
   96c92:	1b00                	addi	s0,sp,432
   96c94:	84ae                	mv	s1,a1
   96c96:	892a                	mv	s2,a0
d_print_init():
   96c98:	f4043823          	sd	zero,-176(s0)
   96c9c:	f4040c23          	sb	zero,-168(s0)
   96ca0:	f6c43023          	sd	a2,-160(s0)
   96ca4:	f6d43423          	sd	a3,-152(s0)
   96ca8:	f6043823          	sd	zero,-144(s0)
   96cac:	f6043c23          	sd	zero,-136(s0)
   96cb0:	f8042023          	sw	zero,-128(s0)
   96cb4:	f8042223          	sw	zero,-124(s0)
   96cb8:	f8042423          	sw	zero,-120(s0)
   96cbc:	f8042623          	sw	zero,-116(s0)
   96cc0:	f8043823          	sd	zero,-112(s0)
   96cc4:	f8043c23          	sd	zero,-104(s0)
   96cc8:	fa043023          	sd	zero,-96(s0)
   96ccc:	fa043423          	sd	zero,-88(s0)
   96cd0:	fa043823          	sd	zero,-80(s0)
   96cd4:	fa043c23          	sd	zero,-72(s0)
   96cd8:	e5040513          	addi	a0,s0,-432
   96cdc:	223020ef          	jal	996fe <d_count_templates_scopes>
   96ce0:	f8442503          	lw	a0,-124(s0)
   96ce4:	7ff00593          	li	a1,2047
   96ce8:	00a5c463          	blt	a1,a0,96cf0 <cplus_demangle_print_callback+0x6a>
   96cec:	f8042223          	sw	zero,-124(s0)
   96cf0:	fac42503          	lw	a0,-84(s0)
   96cf4:	fbc42583          	lw	a1,-68(s0)
   96cf8:	02a585b3          	mul	a1,a1,a0
   96cfc:	fab42e23          	sw	a1,-68(s0)
   96d00:	fc043023          	sd	zero,-64(s0)
cplus_demangle_print_callback():
   96d04:	00a04363          	bgtz	a0,96d0a <cplus_demangle_print_callback+0x84>
   96d08:	4505                	li	a0,1
   96d0a:	898a                	mv	s3,sp
   96d0c:	0512                	slli	a0,a0,0x4
   96d0e:	40a10533          	sub	a0,sp,a0
   96d12:	812a                	mv	sp,a0
   96d14:	fbc42583          	lw	a1,-68(s0)
   96d18:	00b04363          	bgtz	a1,96d1e <cplus_demangle_print_callback+0x98>
   96d1c:	4585                	li	a1,1
   96d1e:	0592                	slli	a1,a1,0x4
   96d20:	40b105b3          	sub	a1,sp,a1
   96d24:	812e                	mv	sp,a1
   96d26:	faa43023          	sd	a0,-96(s0)
   96d2a:	fab43823          	sd	a1,-80(s0)
   96d2e:	c899                	beqz	s1,96d44 <cplus_demangle_print_callback+0xbe>
   96d30:	40cc                	lw	a1,4(s1)
   96d32:	4505                	li	a0,1
   96d34:	00b54863          	blt	a0,a1,96d44 <cplus_demangle_print_callback+0xbe>
   96d38:	f8442503          	lw	a0,-124(s0)
   96d3c:	40100613          	li	a2,1025
   96d40:	04c54363          	blt	a0,a2,96d86 <cplus_demangle_print_callback+0x100>
   96d44:	4505                	li	a0,1
d_print_error():
   96d46:	f8a42023          	sw	a0,-128(s0)
cplus_demangle_print_callback():
   96d4a:	814e                	mv	sp,s3
d_print_flush():
   96d4c:	f5043503          	ld	a0,-176(s0)
   96d50:	e5040593          	addi	a1,s0,-432
   96d54:	952e                	add	a0,a0,a1
   96d56:	00050023          	sb	zero,0(a0)
   96d5a:	f5043583          	ld	a1,-176(s0)
   96d5e:	f6043683          	ld	a3,-160(s0)
   96d62:	f6843603          	ld	a2,-152(s0)
   96d66:	e5040513          	addi	a0,s0,-432
   96d6a:	9682                	jalr	a3
d_print_saw_error():
   96d6c:	f8042503          	lw	a0,-128(s0)
   96d70:	00153513          	seqz	a0,a0
cplus_demangle_print_callback():
   96d74:	e5040113          	addi	sp,s0,-432
   96d78:	70ba                	ld	ra,424(sp)
   96d7a:	741a                	ld	s0,416(sp)
   96d7c:	64fa                	ld	s1,408(sp)
   96d7e:	695a                	ld	s2,400(sp)
   96d80:	69ba                	ld	s3,392(sp)
   96d82:	615d                	addi	sp,sp,432
   96d84:	8082                	ret
   96d86:	0585                	addi	a1,a1,1
   96d88:	f9843603          	ld	a2,-104(s0)
   96d8c:	c0cc                	sw	a1,4(s1)
   96d8e:	0505                	addi	a0,a0,1
   96d90:	fc943423          	sd	s1,-56(s0)
   96d94:	fcc43823          	sd	a2,-48(s0)
   96d98:	fc840593          	addi	a1,s0,-56
   96d9c:	f8a42223          	sw	a0,-124(s0)
   96da0:	f8b43c23          	sd	a1,-104(s0)
   96da4:	e5040513          	addi	a0,s0,-432
   96da8:	85ca                	mv	a1,s2
   96daa:	8626                	mv	a2,s1
   96dac:	1ed020ef          	jal	99798 <d_print_comp_inner>
   96db0:	f8442503          	lw	a0,-124(s0)
   96db4:	fd043583          	ld	a1,-48(s0)
   96db8:	40d0                	lw	a2,4(s1)
   96dba:	157d                	addi	a0,a0,-1
   96dbc:	f8a42223          	sw	a0,-124(s0)
   96dc0:	f8b43c23          	sd	a1,-104(s0)
   96dc4:	167d                	addi	a2,a2,-1
   96dc6:	c0d0                	sw	a2,4(s1)
   96dc8:	b749                	j	96d4a <cplus_demangle_print_callback+0xc4>

0000000000016e88 <_ZNK6driver12set_up_specsEv>:
_ZNK6driver12set_up_specsEv():
   16e88:	7115                	addi	sp,sp,-224
   16e8a:	ed86                	sd	ra,216(sp)
   16e8c:	e9a2                	sd	s0,208(sp)
   16e8e:	e5a6                	sd	s1,200(sp)
   16e90:	e1ca                	sd	s2,192(sp)
   16e92:	fd4e                	sd	s3,184(sp)
   16e94:	f952                	sd	s4,176(sp)
   16e96:	f556                	sd	s5,168(sp)
   16e98:	f15a                	sd	s6,160(sp)
   16e9a:	ed5e                	sd	s7,152(sp)
   16e9c:	e962                	sd	s8,144(sp)
   16e9e:	e566                	sd	s9,136(sp)
   16ea0:	e16a                	sd	s10,128(sp)
   16ea2:	fcee                	sd	s11,120(sp)
   16ea4:	1180                	addi	s0,sp,224
   16ea6:	650c                	ld	a1,8(a0)
   16ea8:	4908                	lw	a0,16(a0)
   16eaa:	173020ef          	jal	1981c <_ZL15process_commandjP17cl_decoded_option>
   16eae:	68000513          	li	a0,1664
   16eb2:	42b8a0ef          	jal	a1adc <xmalloc>
   16eb6:	001a4db7          	lui	s11,0x1a4
   16eba:	050d8d93          	addi	s11,s11,80 # 1a4050 <_ZL16at_file_supplied>
   16ebe:	12adb023          	sd	a0,288(s11)
   16ec2:	000a35b7          	lui	a1,0xa3
   16ec6:	82858593          	addi	a1,a1,-2008 # a2828 <_ZL17default_compilers>
   16eca:	68000613          	li	a2,1664
   16ece:	de2fd0ef          	jal	144b0 <memcpy@plt>
   16ed2:	03300513          	li	a0,51
   16ed6:	04ada823          	sw	a0,80(s11)
   16eda:	000a49b7          	lui	s3,0xa4
   16ede:	93198993          	addi	s3,s3,-1743 # a3931 <_ZL12thread_model+0x67c>
   16ee2:	000a3637          	lui	a2,0xa3
   16ee6:	37f60613          	addi	a2,a2,895 # a337f <_ZL12thread_model+0xca>
   16eea:	000e5937          	lui	s2,0xe5
   16eee:	f5e90913          	addi	s2,s2,-162 # e4f5e <_ZZ13trim_filenamePKcE9this_file+0x1a44>
   16ef2:	000a34b7          	lui	s1,0xa3
   16ef6:	ea848493          	addi	s1,s1,-344 # a2ea8 <_ZL17dir_separator_str>
   16efa:	854e                	mv	a0,s3
   16efc:	85a6                	mv	a1,s1
   16efe:	86ca                	mv	a3,s2
   16f00:	8726                	mv	a4,s1
   16f02:	4781                	li	a5,0
   16f04:	0fc880ef          	jal	9f000 <concat>
   16f08:	12adb423          	sd	a0,296(s11)
   16f0c:	854e                	mv	a0,s3
   16f0e:	85a6                	mv	a1,s1
   16f10:	4601                	li	a2,0
   16f12:	0ee880ef          	jal	9f000 <concat>
   16f16:	12adb823          	sd	a0,304(s11)
_ZL11find_a_filePK11path_prefixPKcib():
   16f1a:	000c7537          	lui	a0,0xc7
   16f1e:	b9f50513          	addi	a0,a0,-1121 # c6b9f <_ZZL9init_specvE2tf+0x2160b>
   16f22:	4595                	li	a1,5
   16f24:	4611                	li	a2,4
   16f26:	f6a43c23          	sd	a0,-136(s0)
   16f2a:	f9243023          	sd	s2,-128(s0)
   16f2e:	f8b43423          	sd	a1,-120(s0)
   16f32:	f8c42823          	sw	a2,-112(s0)
   16f36:	001a4c37          	lui	s8,0x1a4
   16f3a:	e80c0c13          	addi	s8,s8,-384 # 1a3e80 <_ZL15greatest_status>
   16f3e:	000226b7          	lui	a3,0x22
   16f42:	a1068693          	addi	a3,a3,-1520 # 21a10 <_ZL12file_at_pathPcPv>
   16f46:	4585                	li	a1,1
   16f48:	4615                	li	a2,5
   16f4a:	0c0c0a13          	addi	s4,s8,192
   16f4e:	f7840713          	addi	a4,s0,-136
   16f52:	8552                	mv	a0,s4
   16f54:	0070a0ef          	jal	2175a <_ZL13for_each_pathPK11path_prefixbmPFPvPcS2_ES2_>
_ZNK6driver12set_up_specsEv():
   16f58:	cd19                	beqz	a0,16f76 <_ZNK6driver12set_up_specsEv+0xee>
   16f5a:	84aa                	mv	s1,a0
   16f5c:	000c75b7          	lui	a1,0xc7
   16f60:	b9f58593          	addi	a1,a1,-1121 # c6b9f <_ZZL9init_specvE2tf+0x2160b>
   16f64:	f0dfc0ef          	jal	13e70 <strcmp@plt>
   16f68:	c519                	beqz	a0,16f76 <_ZNK6driver12set_up_specsEv+0xee>
   16f6a:	4585                	li	a1,1
   16f6c:	8526                	mv	a0,s1
   16f6e:	4601                	li	a2,0
   16f70:	7ad030ef          	jal	1af1c <_ZL10read_specsPKcbb>
   16f74:	a019                	j	16f7a <_ZNK6driver12set_up_specsEv+0xf2>
   16f76:	78c040ef          	jal	1b702 <_ZL9init_specv>
   16f7a:	130db903          	ld	s2,304(s11)
   16f7e:	854a                	mv	a0,s2
   16f80:	8b0fd0ef          	jal	14030 <strlen@plt>
   16f84:	06650513          	addi	a0,a0,102
   16f88:	9941                	andi	a0,a0,-16
   16f8a:	40a104b3          	sub	s1,sp,a0
   16f8e:	8126                	mv	sp,s1
   16f90:	000a39b7          	lui	s3,0xa3
   16f94:	38698993          	addi	s3,s3,902 # a3386 <_ZL12thread_model+0xd1>
   16f98:	04000513          	li	a0,64
   16f9c:	0c257057          	vsetvli	zero,a0,e8,m4,ta,ma
   16fa0:	02098407          	vle8.v	v8,(s3)
   16fa4:	02f00513          	li	a0,47
   16fa8:	02048427          	vse8.v	v8,(s1)
   16fac:	04098593          	addi	a1,s3,64
   16fb0:	cc087057          	vsetivli	zero,16,e8,m1,ta,ma
   16fb4:	02058407          	vle8.v	v8,(a1)
   16fb8:	04a48823          	sb	a0,80(s1)
   16fbc:	040488a3          	sb	zero,81(s1)
   16fc0:	04048513          	addi	a0,s1,64
   16fc4:	02050427          	vse8.v	v8,(a0)
   16fc8:	8526                	mv	a0,s1
   16fca:	85ca                	mv	a1,s2
   16fcc:	814fd0ef          	jal	13fe0 <strcat@plt>
   16fd0:	8526                	mv	a0,s1
   16fd2:	85efd0ef          	jal	14030 <strlen@plt>
   16fd6:	9526                	add	a0,a0,s1
   16fd8:	07300593          	li	a1,115
   16fdc:	07000613          	li	a2,112
   16fe0:	06500693          	li	a3,101
   16fe4:	06300713          	li	a4,99
   16fe8:	00b50023          	sb	a1,0(a0)
   16fec:	00c500a3          	sb	a2,1(a0)
   16ff0:	00d50123          	sb	a3,2(a0)
   16ff4:	00e501a3          	sb	a4,3(a0)
   16ff8:	00b50223          	sb	a1,4(a0)
   16ffc:	000502a3          	sb	zero,5(a0)
   17000:	4591                	li	a1,4
   17002:	8526                	mv	a0,s1
   17004:	84cfd0ef          	jal	14050 <access@plt>
   17008:	e511                	bnez	a0,17014 <_ZNK6driver12set_up_specsEv+0x18c>
   1700a:	4585                	li	a1,1
   1700c:	8526                	mv	a0,s1
   1700e:	4601                	li	a2,0
   17010:	70d030ef          	jal	1af1c <_ZL10read_specsPKcbb>
   17014:	000a6537          	lui	a0,0xa6
   17018:	66250513          	addi	a0,a0,1634 # a6662 <_ZZL9init_specvE2tf+0x10ce>
   1701c:	000a55b7          	lui	a1,0xa5
   17020:	73858593          	addi	a1,a1,1848 # a5738 <_ZZL9init_specvE2tf+0x1a4>
   17024:	4d1040ef          	jal	1bcf4 <_ZL14do_option_specPKcS0_>
   17028:	000a6537          	lui	a0,0xa6
   1702c:	63350513          	addi	a0,a0,1587 # a6633 <_ZZL9init_specvE2tf+0x109f>
   17030:	000a55b7          	lui	a1,0xa5
   17034:	79658593          	addi	a1,a1,1942 # a5796 <_ZZL9init_specvE2tf+0x202>
   17038:	4bd040ef          	jal	1bcf4 <_ZL14do_option_specPKcS0_>
   1703c:	000bb537          	lui	a0,0xbb
   17040:	73650513          	addi	a0,a0,1846 # bb736 <_ZZL9init_specvE2tf+0x161a2>
   17044:	000a55b7          	lui	a1,0xa5
   17048:	7f458593          	addi	a1,a1,2036 # a57f4 <_ZZL9init_specvE2tf+0x260>
   1704c:	4a9040ef          	jal	1bcf4 <_ZL14do_option_specPKcS0_>
   17050:	000a5537          	lui	a0,0xa5
   17054:	72650513          	addi	a0,a0,1830 # a5726 <_ZZL9init_specvE2tf+0x192>
   17058:	000a65b7          	lui	a1,0xa6
   1705c:	80e58593          	addi	a1,a1,-2034 # a580e <_ZZL9init_specvE2tf+0x27a>
   17060:	495040ef          	jal	1bcf4 <_ZL14do_option_specPKcS0_>
   17064:	000de537          	lui	a0,0xde
   17068:	0cc50513          	addi	a0,a0,204 # de0cc <_ZZL9init_specvE2tf+0x38b38>
   1706c:	000a65b7          	lui	a1,0xa6
   17070:	83258593          	addi	a1,a1,-1998 # a5832 <_ZZL9init_specvE2tf+0x29e>
   17074:	481040ef          	jal	1bcf4 <_ZL14do_option_specPKcS0_>
   17078:	000a6537          	lui	a0,0xa6
   1707c:	8a550513          	addi	a0,a0,-1883 # a58a5 <_ZZL9init_specvE2tf+0x311>
   17080:	5ab040ef          	jal	1be2a <_ZL12do_self_specPKc>
   17084:	000a6537          	lui	a0,0xa6
   17088:	8e350513          	addi	a0,a0,-1821 # a58e3 <_ZZL9init_specvE2tf+0x34f>
   1708c:	59f040ef          	jal	1be2a <_ZL12do_self_specPKc>
   17090:	000e5937          	lui	s2,0xe5
   17094:	f5e90913          	addi	s2,s2,-162 # e4f5e <_ZZ13trim_filenamePKcE9this_file+0x1a44>
   17098:	854a                	mv	a0,s2
   1709a:	591040ef          	jal	1be2a <_ZL12do_self_specPKc>
   1709e:	000a6537          	lui	a0,0xa6
   170a2:	9c550513          	addi	a0,a0,-1595 # a59c5 <_ZZL9init_specvE2tf+0x431>
   170a6:	585040ef          	jal	1be2a <_ZL12do_self_specPKc>
   170aa:	000a6537          	lui	a0,0xa6
   170ae:	a0b50513          	addi	a0,a0,-1525 # a5a0b <_ZZL9init_specvE2tf+0x477>
   170b2:	579040ef          	jal	1be2a <_ZL12do_self_specPKc>
   170b6:	000a6537          	lui	a0,0xa6
   170ba:	a2050513          	addi	a0,a0,-1504 # a5a20 <_ZZL9init_specvE2tf+0x48c>
   170be:	56d040ef          	jal	1be2a <_ZL12do_self_specPKc>
   170c2:	008c3503          	ld	a0,8(s8)
   170c6:	00054503          	lbu	a0,0(a0)
   170ca:	03000593          	li	a1,48
   170ce:	06b51763          	bne	a0,a1,1713c <_ZNK6driver12set_up_specsEv+0x2b4>
   170d2:	010c3503          	ld	a0,16(s8)
   170d6:	00054583          	lbu	a1,0(a0)
   170da:	c1ad                	beqz	a1,1713c <_ZNK6driver12set_up_specsEv+0x2b4>
_ZL10add_prefixP11path_prefixPKcS2_iii():
   170dc:	0d8c3583          	ld	a1,216(s8)
   170e0:	0d8c0a93          	addi	s5,s8,216
   170e4:	cd81                	beqz	a1,170fc <_ZNK6driver12set_up_specsEv+0x274>
   170e6:	49d4                	lw	a3,20(a1)
   170e8:	4605                	li	a2,1
   170ea:	00d64963          	blt	a2,a3,170fc <_ZNK6driver12set_up_specsEv+0x274>
   170ee:	8aae                	mv	s5,a1
   170f0:	658c                	ld	a1,8(a1)
   170f2:	c581                	beqz	a1,170fa <_ZNK6driver12set_up_specsEv+0x272>
   170f4:	49d4                	lw	a3,20(a1)
   170f6:	fed65ce3          	bge	a2,a3,170ee <_ZNK6driver12set_up_specsEv+0x266>
   170fa:	0aa1                	addi	s5,s5,8
   170fc:	000a35b7          	lui	a1,0xa3
   17100:	3d858593          	addi	a1,a1,984 # a33d8 <_ZL12thread_model+0x123>
   17104:	2ae150ef          	jal	2c3b2 <update_path>
   17108:	84aa                	mv	s1,a0
   1710a:	f27fc0ef          	jal	14030 <strlen@plt>
   1710e:	0e0c2583          	lw	a1,224(s8)
   17112:	0005061b          	sext.w	a2,a0
   17116:	00c5d463          	bge	a1,a2,1711e <_ZNK6driver12set_up_specsEv+0x296>
   1711a:	0eac2023          	sw	a0,224(s8)
   1711e:	02000513          	li	a0,32
   17122:	1bb8a0ef          	jal	a1adc <xmalloc>
   17126:	4585                	li	a1,1
   17128:	1582                	slli	a1,a1,0x20
   1712a:	e104                	sd	s1,0(a0)
   1712c:	e90c                	sd	a1,16(a0)
   1712e:	00052c23          	sw	zero,24(a0)
   17132:	000ab583          	ld	a1,0(s5)
   17136:	e50c                	sd	a1,8(a0)
   17138:	00aab023          	sd	a0,0(s5)
_ZNK6driver12set_up_specsEv():
   1713c:	018c3503          	ld	a0,24(s8)
   17140:	00054583          	lbu	a1,0(a0)
   17144:	001a4bb7          	lui	s7,0x1a4
   17148:	c5a9                	beqz	a1,17192 <_ZNK6driver12set_up_specsEv+0x30a>
   1714a:	6a4ba583          	lw	a1,1700(s7) # 1a46a4 <global_options+0x13c>
   1714e:	e1b1                	bnez	a1,17192 <_ZNK6driver12set_up_specsEv+0x30a>
_ZN3vecIPKc7va_heap6vl_ptrE8truncateEj():
   17150:	0c8db583          	ld	a1,200(s11)
   17154:	c199                	beqz	a1,1715a <_ZNK6driver12set_up_specsEv+0x2d2>
_ZN3vecIPKc7va_heap8vl_embedE8truncateEj():
   17156:	0005a223          	sw	zero,4(a1)
_ZN3vecIPKc7va_heap6vl_ptrE8truncateEj():
   1715a:	238db583          	ld	a1,568(s11)
   1715e:	c199                	beqz	a1,17164 <_ZNK6driver12set_up_specsEv+0x2dc>
_ZN3vecIPKc7va_heap8vl_embedE8truncateEj():
   17160:	0005a223          	sw	zero,4(a1)
_ZL9do_spec_2PKcS0_():
   17164:	080da623          	sw	zero,140(s11)
   17168:	000d8c23          	sb	zero,24(s11)
   1716c:	000d8e23          	sb	zero,28(s11)
   17170:	020d8023          	sb	zero,32(s11)
   17174:	020d8223          	sb	zero,36(s11)
   17178:	020d8423          	sb	zero,40(s11)
   1717c:	220db823          	sd	zero,560(s11)
   17180:	4581                	li	a1,0
   17182:	4601                	li	a2,0
   17184:	22c050ef          	jal	1c3b0 <_ZL9do_spec_1PKciS0_>
   17188:	84aa                	mv	s1,a0
   1718a:	621080ef          	jal	1ffaa <_ZL13end_going_argv>
_ZNK6driver12set_up_specsEv():
   1718e:	1e0487e3          	beqz	s1,17b7c <_ZNK6driver12set_up_specsEv+0xcf4>
   17192:	140db503          	ld	a0,320(s11)
   17196:	c971                	beqz	a0,1726a <_ZNK6driver12set_up_specsEv+0x3e2>
   17198:	2c0db503          	ld	a0,704(s11)
   1719c:	2c8db583          	ld	a1,712(s11)
   171a0:	8d89                	sub	a1,a1,a0
   171a2:	463d                	li	a2,15
   171a4:	00b66963          	bltu	a2,a1,171b6 <_ZNK6driver12set_up_specsEv+0x32e>
   171a8:	2a8d8513          	addi	a0,s11,680
   171ac:	45c1                	li	a1,16
   171ae:	30b890ef          	jal	a0cb8 <_obstack_newchunk>
   171b2:	2c0db503          	ld	a0,704(s11)
   171b6:	000a35b7          	lui	a1,0xa3
   171ba:	41c58593          	addi	a1,a1,1052 # a341c <_ZL12thread_model+0x167>
   171be:	cc087057          	vsetivli	zero,16,e8,m1,ta,ma
   171c2:	02058407          	vle8.v	v8,(a1)
   171c6:	02050427          	vse8.v	v8,(a0)
   171ca:	2c0db483          	ld	s1,704(s11)
   171ce:	020c3a83          	ld	s5,32(s8)
   171d2:	04c1                	addi	s1,s1,16
   171d4:	2c9db023          	sd	s1,704(s11)
   171d8:	8556                	mv	a0,s5
   171da:	e57fc0ef          	jal	14030 <strlen@plt>
   171de:	8b2a                	mv	s6,a0
   171e0:	2c8db503          	ld	a0,712(s11)
   171e4:	8d05                	sub	a0,a0,s1
   171e6:	001b0593          	addi	a1,s6,1
   171ea:	00b57a63          	bgeu	a0,a1,171fe <_ZNK6driver12set_up_specsEv+0x376>
   171ee:	2a8d8513          	addi	a0,s11,680
   171f2:	2c7890ef          	jal	a0cb8 <_obstack_newchunk>
   171f6:	2c0db483          	ld	s1,704(s11)
   171fa:	020c3a83          	ld	s5,32(s8)
   171fe:	8526                	mv	a0,s1
   17200:	85d6                	mv	a1,s5
   17202:	865a                	mv	a2,s6
   17204:	aacfd0ef          	jal	144b0 <memcpy@plt>
   17208:	2c0db503          	ld	a0,704(s11)
   1720c:	955a                	add	a0,a0,s6
   1720e:	00150593          	addi	a1,a0,1
   17212:	2cbdb023          	sd	a1,704(s11)
   17216:	00050023          	sb	zero,0(a0)
   1721a:	2b8db583          	ld	a1,696(s11)
   1721e:	2c0db503          	ld	a0,704(s11)
   17222:	00b51863          	bne	a0,a1,17232 <_ZNK6driver12set_up_specsEv+0x3aa>
   17226:	2f8dc603          	lbu	a2,760(s11)
   1722a:	00266613          	ori	a2,a2,2
   1722e:	2ecd8c23          	sb	a2,760(s11)
   17232:	2d8db683          	ld	a3,728(s11)
   17236:	2b0db703          	ld	a4,688(s11)
   1723a:	2c8db603          	ld	a2,712(s11)
   1723e:	9536                	add	a0,a0,a3
   17240:	fff6c693          	not	a3,a3
   17244:	8d75                	and	a0,a0,a3
   17246:	40e506b3          	sub	a3,a0,a4
   1724a:	40e60733          	sub	a4,a2,a4
   1724e:	00d76363          	bltu	a4,a3,17254 <_ZNK6driver12set_up_specsEv+0x3cc>
   17252:	862a                	mv	a2,a0
   17254:	2acdbc23          	sd	a2,696(s11)
   17258:	2ccdb023          	sd	a2,704(s11)
   1725c:	000bd537          	lui	a0,0xbd
   17260:	67650513          	addi	a0,a0,1654 # bd676 <_ZZL9init_specvE2tf+0x180e2>
   17264:	4601                	li	a2,0
   17266:	6c5040ef          	jal	1c12a <_ZL8set_specPKcS0_b>
   1726a:	028c3503          	ld	a0,40(s8)
   1726e:	00054583          	lbu	a1,0(a0)
   17272:	c5a9                	beqz	a1,172bc <_ZNK6driver12set_up_specsEv+0x434>
   17274:	6a4ba583          	lw	a1,1700(s7)
   17278:	e1b1                	bnez	a1,172bc <_ZNK6driver12set_up_specsEv+0x434>
_ZN3vecIPKc7va_heap6vl_ptrE8truncateEj():
   1727a:	0c8db583          	ld	a1,200(s11)
   1727e:	c199                	beqz	a1,17284 <_ZNK6driver12set_up_specsEv+0x3fc>
_ZN3vecIPKc7va_heap8vl_embedE8truncateEj():
   17280:	0005a223          	sw	zero,4(a1)
_ZN3vecIPKc7va_heap6vl_ptrE8truncateEj():
   17284:	238db583          	ld	a1,568(s11)
   17288:	c199                	beqz	a1,1728e <_ZNK6driver12set_up_specsEv+0x406>
_ZN3vecIPKc7va_heap8vl_embedE8truncateEj():
   1728a:	0005a223          	sw	zero,4(a1)
_ZL9do_spec_2PKcS0_():
   1728e:	080da623          	sw	zero,140(s11)
   17292:	000d8c23          	sb	zero,24(s11)
   17296:	000d8e23          	sb	zero,28(s11)
   1729a:	020d8023          	sb	zero,32(s11)
   1729e:	020d8223          	sb	zero,36(s11)
   172a2:	020d8423          	sb	zero,40(s11)
   172a6:	220db823          	sd	zero,560(s11)
   172aa:	4581                	li	a1,0
   172ac:	4601                	li	a2,0
   172ae:	102050ef          	jal	1c3b0 <_ZL9do_spec_1PKciS0_>
   172b2:	84aa                	mv	s1,a0
   172b4:	4f7080ef          	jal	1ffaa <_ZL13end_going_argv>
_ZNK6driver12set_up_specsEv():
   172b8:	0e0482e3          	beqz	s1,17b9c <_ZNK6driver12set_up_specsEv+0xd14>
   172bc:	030c3503          	ld	a0,48(s8)
   172c0:	00054583          	lbu	a1,0(a0)
   172c4:	c9b9                	beqz	a1,1731a <_ZNK6driver12set_up_specsEv+0x492>
_ZN3vecIPKc7va_heap6vl_ptrE8truncateEj():
   172c6:	0c8db583          	ld	a1,200(s11)
   172ca:	c199                	beqz	a1,172d0 <_ZNK6driver12set_up_specsEv+0x448>
_ZN3vecIPKc7va_heap8vl_embedE8truncateEj():
   172cc:	0005a223          	sw	zero,4(a1)
_ZN3vecIPKc7va_heap6vl_ptrE8truncateEj():
   172d0:	238db583          	ld	a1,568(s11)
   172d4:	c199                	beqz	a1,172da <_ZNK6driver12set_up_specsEv+0x452>
_ZN3vecIPKc7va_heap8vl_embedE8truncateEj():
   172d6:	0005a223          	sw	zero,4(a1)
_ZL9do_spec_2PKcS0_():
   172da:	080da623          	sw	zero,140(s11)
   172de:	000d8c23          	sb	zero,24(s11)
   172e2:	000d8e23          	sb	zero,28(s11)
   172e6:	020d8023          	sb	zero,32(s11)
   172ea:	020d8223          	sb	zero,36(s11)
   172ee:	020d8423          	sb	zero,40(s11)
   172f2:	220db823          	sd	zero,560(s11)
   172f6:	4581                	li	a1,0
   172f8:	4601                	li	a2,0
   172fa:	0b6050ef          	jal	1c3b0 <_ZL9do_spec_1PKciS0_>
   172fe:	84aa                	mv	s1,a0
   17300:	4ab080ef          	jal	1ffaa <_ZL13end_going_argv>
_ZNK6driver12set_up_specsEv():
   17304:	e899                	bnez	s1,1731a <_ZNK6driver12set_up_specsEv+0x492>
   17306:	000e5537          	lui	a0,0xe5
   1730a:	0dc50513          	addi	a0,a0,220 # e50dc <_ZZ13trim_filenamePKcE9this_file+0x1bc2>
   1730e:	4581                	li	a1,0
   17310:	4601                	li	a2,0
   17312:	09e050ef          	jal	1c3b0 <_ZL9do_spec_1PKciS0_>
   17316:	0a0503e3          	beqz	a0,17bbc <_ZNK6driver12set_up_specsEv+0xd34>
   1731a:	008c3503          	ld	a0,8(s8)
   1731e:	00054503          	lbu	a0,0(a0)
   17322:	03000593          	li	a1,48
   17326:	00b50563          	beq	a0,a1,17330 <_ZNK6driver12set_up_specsEv+0x4a8>
   1732a:	140db503          	ld	a0,320(s11)
   1732e:	cd61                	beqz	a0,17406 <_ZNK6driver12set_up_specsEv+0x57e>
   17330:	038c3503          	ld	a0,56(s8)
   17334:	00054583          	lbu	a1,0(a0)
   17338:	c599                	beqz	a1,17346 <_ZNK6driver12set_up_specsEv+0x4be>
   1733a:	000a35b7          	lui	a1,0xa3
   1733e:	3d858593          	addi	a1,a1,984 # a33d8 <_ZL12thread_model+0x123>
   17342:	7e7060ef          	jal	1e328 <_ZL20add_sysrooted_prefixP11path_prefixPKcS2_iii>
   17346:	040c3503          	ld	a0,64(s8)
   1734a:	00054583          	lbu	a1,0(a0)
   1734e:	c599                	beqz	a1,1735c <_ZNK6driver12set_up_specsEv+0x4d4>
   17350:	000a35b7          	lui	a1,0xa3
   17354:	3d858593          	addi	a1,a1,984 # a33d8 <_ZL12thread_model+0x123>
   17358:	7d1060ef          	jal	1e328 <_ZL20add_sysrooted_prefixP11path_prefixPKcS2_iii>
   1735c:	008c3503          	ld	a0,8(s8)
   17360:	00054503          	lbu	a0,0(a0)
   17364:	03000593          	li	a1,48
   17368:	06b51d63          	bne	a0,a1,173e2 <_ZNK6driver12set_up_specsEv+0x55a>
   1736c:	150db503          	ld	a0,336(s11)
   17370:	c111                	beqz	a0,17374 <_ZNK6driver12set_up_specsEv+0x4ec>
   17372:	89aa                	mv	s3,a0
   17374:	128db583          	ld	a1,296(s11)
   17378:	000a5637          	lui	a2,0xa5
   1737c:	92d60613          	addi	a2,a2,-1747 # a492d <_ZL12thread_model+0x1678>
   17380:	854e                	mv	a0,s3
   17382:	4681                	li	a3,0
   17384:	47d870ef          	jal	9f000 <concat>
_ZL10add_prefixP11path_prefixPKcS2_iii():
   17388:	0c0c3583          	ld	a1,192(s8)
   1738c:	89d2                	mv	s3,s4
   1738e:	cd89                	beqz	a1,173a8 <_ZNK6driver12set_up_specsEv+0x520>
   17390:	49d4                	lw	a3,20(a1)
   17392:	4605                	li	a2,1
   17394:	89d2                	mv	s3,s4
   17396:	00d64963          	blt	a2,a3,173a8 <_ZNK6driver12set_up_specsEv+0x520>
   1739a:	89ae                	mv	s3,a1
   1739c:	658c                	ld	a1,8(a1)
   1739e:	c581                	beqz	a1,173a6 <_ZNK6driver12set_up_specsEv+0x51e>
   173a0:	49d4                	lw	a3,20(a1)
   173a2:	fed65ce3          	bge	a2,a3,1739a <_ZNK6driver12set_up_specsEv+0x512>
   173a6:	09a1                	addi	s3,s3,8
   173a8:	4581                	li	a1,0
   173aa:	008150ef          	jal	2c3b2 <update_path>
   173ae:	84aa                	mv	s1,a0
   173b0:	c81fc0ef          	jal	14030 <strlen@plt>
   173b4:	0c8c2583          	lw	a1,200(s8)
   173b8:	0005061b          	sext.w	a2,a0
   173bc:	00c5d463          	bge	a1,a2,173c4 <_ZNK6driver12set_up_specsEv+0x53c>
   173c0:	0cac2423          	sw	a0,200(s8)
   173c4:	02000513          	li	a0,32
   173c8:	7148a0ef          	jal	a1adc <xmalloc>
   173cc:	4585                	li	a1,1
   173ce:	02059613          	slli	a2,a1,0x20
   173d2:	e104                	sd	s1,0(a0)
   173d4:	e910                	sd	a2,16(a0)
   173d6:	cd0c                	sw	a1,24(a0)
   173d8:	0009b583          	ld	a1,0(s3)
   173dc:	e50c                	sd	a1,8(a0)
   173de:	00a9b023          	sd	a0,0(s3)
_ZNK6driver12set_up_specsEv():
   173e2:	000a3537          	lui	a0,0xa3
   173e6:	48250513          	addi	a0,a0,1154 # a3482 <_ZL12thread_model+0x1cd>
   173ea:	000a34b7          	lui	s1,0xa3
   173ee:	47548493          	addi	s1,s1,1141 # a3475 <_ZL12thread_model+0x1c0>
   173f2:	85a6                	mv	a1,s1
   173f4:	735060ef          	jal	1e328 <_ZL20add_sysrooted_prefixP11path_prefixPKcS2_iii>
   173f8:	000a3537          	lui	a0,0xa3
   173fc:	47e50513          	addi	a0,a0,1150 # a347e <_ZL12thread_model+0x1c9>
   17400:	85a6                	mv	a1,s1
   17402:	727060ef          	jal	1e328 <_ZL20add_sysrooted_prefixP11path_prefixPKcS2_iii>
   17406:	158dba83          	ld	s5,344(s11)
   1740a:	060a8c63          	beqz	s5,17482 <_ZNK6driver12set_up_specsEv+0x5fa>
   1740e:	02f00b13          	li	s6,47
   17412:	4b91                	li	s7,4
   17414:	000229b7          	lui	s3,0x22
   17418:	a1098993          	addi	s3,s3,-1520 # 21a10 <_ZL12file_at_pathPcPv>
   1741c:	a005                	j	1743c <_ZNK6driver12set_up_specsEv+0x5b4>
   1741e:	4591                	li	a1,4
   17420:	8526                	mv	a0,s1
   17422:	c2ffc0ef          	jal	14050 <access@plt>
   17426:	c929                	beqz	a0,17478 <_ZNK6driver12set_up_specsEv+0x5f0>
   17428:	008ab503          	ld	a0,8(s5)
   1742c:	4605                	li	a2,1
   1742e:	4581                	li	a1,0
   17430:	2ed030ef          	jal	1af1c <_ZL10read_specsPKcbb>
   17434:	000aba83          	ld	s5,0(s5)
   17438:	040a8563          	beqz	s5,17482 <_ZNK6driver12set_up_specsEv+0x5fa>
   1743c:	008ab483          	ld	s1,8(s5)
   17440:	0004c503          	lbu	a0,0(s1)
   17444:	fd650de3          	beq	a0,s6,1741e <_ZNK6driver12set_up_specsEv+0x596>
   17448:	f6943c23          	sd	s1,-136(s0)
   1744c:	f9243023          	sd	s2,-128(s0)
   17450:	8526                	mv	a0,s1
   17452:	bdffc0ef          	jal	14030 <strlen@plt>
   17456:	f8a42423          	sw	a0,-120(s0)
   1745a:	f8042623          	sw	zero,-116(s0)
   1745e:	f9742823          	sw	s7,-112(s0)
   17462:	0005061b          	sext.w	a2,a0
   17466:	4585                	li	a1,1
   17468:	f7840713          	addi	a4,s0,-136
   1746c:	8552                	mv	a0,s4
   1746e:	86ce                	mv	a3,s3
   17470:	2ea0a0ef          	jal	2175a <_ZL13for_each_pathPK11path_prefixbmPFPvPcS2_ES2_>
   17474:	fd45                	bnez	a0,1742c <_ZNK6driver12set_up_specsEv+0x5a4>
   17476:	bf4d                	j	17428 <_ZNK6driver12set_up_specsEv+0x5a0>
   17478:	8526                	mv	a0,s1
   1747a:	7288a0ef          	jal	a1ba2 <xstrdup>
   1747e:	f55d                	bnez	a0,1742c <_ZNK6driver12set_up_specsEv+0x5a4>
   17480:	b765                	j	17428 <_ZNK6driver12set_up_specsEv+0x5a0>
   17482:	160db483          	ld	s1,352(s11)
   17486:	c495                	beqz	s1,174b2 <_ZNK6driver12set_up_specsEv+0x62a>
   17488:	49a5                	li	s3,9
   1748a:	000a3937          	lui	s2,0xa3
   1748e:	48890913          	addi	s2,s2,1160 # a3488 <_ZL12thread_model+0x1d3>
   17492:	a019                	j	17498 <_ZNK6driver12set_up_specsEv+0x610>
   17494:	6c84                	ld	s1,24(s1)
   17496:	cc91                	beqz	s1,174b2 <_ZNK6driver12set_up_specsEv+0x62a>
   17498:	5088                	lw	a0,32(s1)
   1749a:	ff351de3          	bne	a0,s3,17494 <_ZNK6driver12set_up_specsEv+0x60c>
   1749e:	6088                	ld	a0,0(s1)
   174a0:	85ca                	mv	a1,s2
   174a2:	9cffc0ef          	jal	13e70 <strcmp@plt>
   174a6:	f57d                	bnez	a0,17494 <_ZNK6driver12set_up_specsEv+0x60c>
   174a8:	6888                	ld	a0,16(s1)
   174aa:	6108                	ld	a0,0(a0)
   174ac:	17f040ef          	jal	1be2a <_ZL12do_self_specPKc>
   174b0:	b7d5                	j	17494 <_ZNK6driver12set_up_specsEv+0x60c>
   174b2:	038da503          	lw	a0,56(s11)
   174b6:	c579                	beqz	a0,17584 <_ZNK6driver12set_up_specsEv+0x6fc>
   174b8:	03cda583          	lw	a1,60(s11)
   174bc:	e5ad                	bnez	a1,17526 <_ZNK6driver12set_up_specsEv+0x69e>
   174be:	054da583          	lw	a1,84(s11)
   174c2:	058da603          	lw	a2,88(s11)
   174c6:	178db503          	ld	a0,376(s11)
   174ca:	16bda623          	sw	a1,364(s11)
   174ce:	16cdaa23          	sw	a2,372(s11)
   174d2:	00361593          	slli	a1,a2,0x3
   174d6:	0616                	slli	a2,a2,0x5
   174d8:	40b605b3          	sub	a1,a2,a1
   174dc:	862e                	mv	a2,a1
   174de:	6848a0ef          	jal	a1b62 <xmemdup>
   174e2:	26adb423          	sd	a0,616(s11)
   174e6:	000a3537          	lui	a0,0xa3
   174ea:	49250513          	addi	a0,a0,1170 # a3492 <_ZL12thread_model+0x1dd>
   174ee:	13d040ef          	jal	1be2a <_ZL12do_self_specPKc>
   174f2:	16cda583          	lw	a1,364(s11)
   174f6:	174da603          	lw	a2,372(s11)
   174fa:	178db683          	ld	a3,376(s11)
   174fe:	038da503          	lw	a0,56(s11)
   17502:	054da703          	lw	a4,84(s11)
   17506:	058da783          	lw	a5,88(s11)
   1750a:	26ddb023          	sd	a3,608(s11)
   1750e:	268db683          	ld	a3,616(s11)
   17512:	04bdaa23          	sw	a1,84(s11)
   17516:	04cdac23          	sw	a2,88(s11)
   1751a:	16eda423          	sw	a4,360(s11)
   1751e:	16fda823          	sw	a5,368(s11)
   17522:	16ddbc23          	sd	a3,376(s11)
   17526:	05cda483          	lw	s1,92(s11)
   1752a:	40a0053b          	negw	a0,a0
   1752e:	02adac23          	sw	a0,56(s11)
   17532:	040dae23          	sw	zero,92(s11)
   17536:	000a3537          	lui	a0,0xa3
   1753a:	49250513          	addi	a0,a0,1170 # a3492 <_ZL12thread_model+0x1dd>
   1753e:	0ed040ef          	jal	1be2a <_ZL12do_self_specPKc>
   17542:	03cda503          	lw	a0,60(s11)
   17546:	049dae23          	sw	s1,92(s11)
   1754a:	ed0d                	bnez	a0,17584 <_ZNK6driver12set_up_specsEv+0x6fc>
   1754c:	168da503          	lw	a0,360(s11)
   17550:	178db583          	ld	a1,376(s11)
   17554:	038da603          	lw	a2,56(s11)
   17558:	054da683          	lw	a3,84(s11)
   1755c:	058da703          	lw	a4,88(s11)
   17560:	26bdb423          	sd	a1,616(s11)
   17564:	260db583          	ld	a1,608(s11)
   17568:	40c0063b          	negw	a2,a2
   1756c:	02cdac23          	sw	a2,56(s11)
   17570:	04adaa23          	sw	a0,84(s11)
   17574:	04adac23          	sw	a0,88(s11)
   17578:	16dda623          	sw	a3,364(s11)
   1757c:	16edaa23          	sw	a4,372(s11)
   17580:	16bdbc23          	sd	a1,376(s11)
   17584:	150db503          	ld	a0,336(s11)
   17588:	c51d                	beqz	a0,175b6 <_ZNK6driver12set_up_specsEv+0x72e>
   1758a:	000a45b7          	lui	a1,0xa4
   1758e:	93158593          	addi	a1,a1,-1743 # a3931 <_ZL12thread_model+0x67c>
   17592:	000a36b7          	lui	a3,0xa3
   17596:	37f68693          	addi	a3,a3,895 # a337f <_ZL12thread_model+0xca>
   1759a:	000e5737          	lui	a4,0xe5
   1759e:	f5e70713          	addi	a4,a4,-162 # e4f5e <_ZZ13trim_filenamePKcE9this_file+0x1a44>
   175a2:	000a3637          	lui	a2,0xa3
   175a6:	ea860613          	addi	a2,a2,-344 # a2ea8 <_ZL17dir_separator_str>
   175aa:	87b2                	mv	a5,a2
   175ac:	4801                	li	a6,0
   175ae:	253870ef          	jal	9f000 <concat>
   175b2:	14adb823          	sd	a0,336(s11)
_ZL21validate_all_switchesv():
   175b6:	120db903          	ld	s2,288(s11)
   175ba:	00893503          	ld	a0,8(s2)
   175be:	c149                	beqz	a0,17640 <_ZNK6driver12set_up_specsEv+0x7b8>
   175c0:	02500493          	li	s1,37
   175c4:	03c00993          	li	s3,60
   175c8:	07b00a13          	li	s4,123
   175cc:	05700a93          	li	s5,87
   175d0:	04000b13          	li	s6,64
   175d4:	a019                	j	175da <_ZNK6driver12set_up_specsEv+0x752>
   175d6:	852e                	mv	a0,a1
   175d8:	ce39                	beqz	a2,17636 <_ZNK6driver12set_up_specsEv+0x7ae>
_ZL27validate_switches_from_specPKcb():
   175da:	00054603          	lbu	a2,0(a0)
   175de:	00150593          	addi	a1,a0,1
   175e2:	fe961ae3          	bne	a2,s1,175d6 <_ZNK6driver12set_up_specsEv+0x74e>
   175e6:	0005c603          	lbu	a2,0(a1)
   175ea:	03360b63          	beq	a2,s3,17620 <_ZNK6driver12set_up_specsEv+0x798>
   175ee:	03460963          	beq	a2,s4,17620 <_ZNK6driver12set_up_specsEv+0x798>
   175f2:	01561a63          	bne	a2,s5,17606 <_ZNK6driver12set_up_specsEv+0x77e>
   175f6:	00254603          	lbu	a2,2(a0)
   175fa:	07b00693          	li	a3,123
   175fe:	00250593          	addi	a1,a0,2
   17602:	02d60063          	beq	a2,a3,17622 <_ZNK6driver12set_up_specsEv+0x79a>
   17606:	852e                	mv	a0,a1
   17608:	fd6619e3          	bne	a2,s6,175da <_ZNK6driver12set_up_specsEv+0x752>
   1760c:	0015c603          	lbu	a2,1(a1)
   17610:	00158513          	addi	a0,a1,1
   17614:	07b00693          	li	a3,123
   17618:	85aa                	mv	a1,a0
   1761a:	fcd610e3          	bne	a2,a3,175da <_ZNK6driver12set_up_specsEv+0x752>
   1761e:	a011                	j	17622 <_ZNK6driver12set_up_specsEv+0x79a>
   17620:	86b2                	mv	a3,a2
   17622:	00158513          	addi	a0,a1,1
   17626:	f8568593          	addi	a1,a3,-123
   1762a:	0015b613          	seqz	a2,a1
   1762e:	4581                	li	a1,0
   17630:	3430c0ef          	jal	24172 <_ZL17validate_switchesPKcbb>
   17634:	b75d                	j	175da <_ZNK6driver12set_up_specsEv+0x752>
_ZL21validate_all_switchesv():
   17636:	02893503          	ld	a0,40(s2)
   1763a:	02090913          	addi	s2,s2,32
   1763e:	fd51                	bnez	a0,175da <_ZNK6driver12set_up_specsEv+0x752>
   17640:	160db903          	ld	s2,352(s11)
   17644:	08090763          	beqz	s2,176d2 <_ZNK6driver12set_up_specsEv+0x84a>
   17648:	02500493          	li	s1,37
   1764c:	03c00a13          	li	s4,60
   17650:	07b00a93          	li	s5,123
   17654:	05700b13          	li	s6,87
   17658:	04000b93          	li	s7,64
   1765c:	a029                	j	17666 <_ZNK6driver12set_up_specsEv+0x7de>
   1765e:	01893903          	ld	s2,24(s2)
   17662:	06090863          	beqz	s2,176d2 <_ZNK6driver12set_up_specsEv+0x84a>
   17666:	01093503          	ld	a0,16(s2)
   1766a:	02494983          	lbu	s3,36(s2)
   1766e:	6108                	ld	a0,0(a0)
   17670:	a019                	j	17676 <_ZNK6driver12set_up_specsEv+0x7ee>
   17672:	852e                	mv	a0,a1
   17674:	d66d                	beqz	a2,1765e <_ZNK6driver12set_up_specsEv+0x7d6>
_ZL27validate_switches_from_specPKcb():
   17676:	00054603          	lbu	a2,0(a0)
   1767a:	00150593          	addi	a1,a0,1
   1767e:	fe961ae3          	bne	a2,s1,17672 <_ZNK6driver12set_up_specsEv+0x7ea>
   17682:	0005c603          	lbu	a2,0(a1)
   17686:	03460b63          	beq	a2,s4,176bc <_ZNK6driver12set_up_specsEv+0x834>
   1768a:	03560963          	beq	a2,s5,176bc <_ZNK6driver12set_up_specsEv+0x834>
   1768e:	01661a63          	bne	a2,s6,176a2 <_ZNK6driver12set_up_specsEv+0x81a>
   17692:	00254603          	lbu	a2,2(a0)
   17696:	07b00693          	li	a3,123
   1769a:	00250593          	addi	a1,a0,2
   1769e:	02d60063          	beq	a2,a3,176be <_ZNK6driver12set_up_specsEv+0x836>
   176a2:	852e                	mv	a0,a1
   176a4:	fd7619e3          	bne	a2,s7,17676 <_ZNK6driver12set_up_specsEv+0x7ee>
   176a8:	0015c603          	lbu	a2,1(a1)
   176ac:	00158513          	addi	a0,a1,1
   176b0:	07b00693          	li	a3,123
   176b4:	85aa                	mv	a1,a0
   176b6:	fcd610e3          	bne	a2,a3,17676 <_ZNK6driver12set_up_specsEv+0x7ee>
   176ba:	a011                	j	176be <_ZNK6driver12set_up_specsEv+0x836>
   176bc:	86b2                	mv	a3,a2
   176be:	00158513          	addi	a0,a1,1
   176c2:	f8568593          	addi	a1,a3,-123
   176c6:	0015b613          	seqz	a2,a1
   176ca:	85ce                	mv	a1,s3
   176cc:	2a70c0ef          	jal	24172 <_ZL17validate_switchesPKcbb>
   176d0:	b75d                	j	17676 <_ZNK6driver12set_up_specsEv+0x7ee>
_ZL21validate_all_switchesv():
   176d2:	068c3503          	ld	a0,104(s8)
   176d6:	02500493          	li	s1,37
   176da:	03c00913          	li	s2,60
   176de:	07b00993          	li	s3,123
   176e2:	05700a13          	li	s4,87
   176e6:	04000a93          	li	s5,64
   176ea:	a019                	j	176f0 <_ZNK6driver12set_up_specsEv+0x868>
   176ec:	852e                	mv	a0,a1
   176ee:	ce39                	beqz	a2,1774c <_ZNK6driver12set_up_specsEv+0x8c4>
_ZL27validate_switches_from_specPKcb():
   176f0:	00054603          	lbu	a2,0(a0)
   176f4:	00150593          	addi	a1,a0,1
   176f8:	fe961ae3          	bne	a2,s1,176ec <_ZNK6driver12set_up_specsEv+0x864>
   176fc:	0005c603          	lbu	a2,0(a1)
   17700:	03260b63          	beq	a2,s2,17736 <_ZNK6driver12set_up_specsEv+0x8ae>
   17704:	03360963          	beq	a2,s3,17736 <_ZNK6driver12set_up_specsEv+0x8ae>
   17708:	01461a63          	bne	a2,s4,1771c <_ZNK6driver12set_up_specsEv+0x894>
   1770c:	00254603          	lbu	a2,2(a0)
   17710:	07b00693          	li	a3,123
   17714:	00250593          	addi	a1,a0,2
   17718:	02d60063          	beq	a2,a3,17738 <_ZNK6driver12set_up_specsEv+0x8b0>
   1771c:	852e                	mv	a0,a1
   1771e:	fd5619e3          	bne	a2,s5,176f0 <_ZNK6driver12set_up_specsEv+0x868>
   17722:	0015c603          	lbu	a2,1(a1)
   17726:	00158513          	addi	a0,a1,1
   1772a:	07b00693          	li	a3,123
   1772e:	85aa                	mv	a1,a0
   17730:	fcd610e3          	bne	a2,a3,176f0 <_ZNK6driver12set_up_specsEv+0x868>
   17734:	a011                	j	17738 <_ZNK6driver12set_up_specsEv+0x8b0>
   17736:	86b2                	mv	a3,a2
   17738:	00158513          	addi	a0,a1,1
   1773c:	f8568593          	addi	a1,a3,-123
   17740:	0015b613          	seqz	a2,a1
   17744:	4581                	li	a1,0
   17746:	22d0c0ef          	jal	24172 <_ZL17validate_switchesPKcbb>
   1774a:	b75d                	j	176f0 <_ZNK6driver12set_up_specsEv+0x868>
_ZNK6driver12set_up_specsEv():
   1774c:	118db503          	ld	a0,280(s11)
   17750:	060daa23          	sw	zero,116(s11)
   17754:	45a5                	li	a1,9
   17756:	02000613          	li	a2,32
   1775a:	a011                	j	1775e <_ZNK6driver12set_up_specsEv+0x8d6>
   1775c:	0505                	addi	a0,a0,1
   1775e:	00054683          	lbu	a3,0(a0)
   17762:	feb68de3          	beq	a3,a1,1775c <_ZNK6driver12set_up_specsEv+0x8d4>
   17766:	fec68be3          	beq	a3,a2,1775c <_ZNK6driver12set_up_specsEv+0x8d4>
   1776a:	14068963          	beqz	a3,178bc <_ZNK6driver12set_up_specsEv+0xa34>
   1776e:	4581                	li	a1,0
   17770:	02000613          	li	a2,32
   17774:	4685                	li	a3,1
   17776:	1682                	slli	a3,a3,0x20
   17778:	20168693          	addi	a3,a3,513
   1777c:	4725                	li	a4,9
   1777e:	2585                	addiw	a1,a1,1
   17780:	06bdaa23          	sw	a1,116(s11)
   17784:	a011                	j	17788 <_ZNK6driver12set_up_specsEv+0x900>
   17786:	0505                	addi	a0,a0,1
   17788:	00054783          	lbu	a5,0(a0)
   1778c:	fef66de3          	bltu	a2,a5,17786 <_ZNK6driver12set_up_specsEv+0x8fe>
   17790:	00f6d4b3          	srl	s1,a3,a5
   17794:	8885                	andi	s1,s1,1
   17796:	d8e5                	beqz	s1,17786 <_ZNK6driver12set_up_specsEv+0x8fe>
   17798:	a021                	j	177a0 <_ZNK6driver12set_up_specsEv+0x918>
   1779a:	00154783          	lbu	a5,1(a0)
   1779e:	0505                	addi	a0,a0,1
   177a0:	0ff7f793          	zext.b	a5,a5
   177a4:	fee78be3          	beq	a5,a4,1779a <_ZNK6driver12set_up_specsEv+0x912>
   177a8:	fec789e3          	beq	a5,a2,1779a <_ZNK6driver12set_up_specsEv+0x912>
   177ac:	fbe9                	bnez	a5,1777e <_ZNK6driver12set_up_specsEv+0x8f6>
   177ae:	00459513          	slli	a0,a1,0x4
   177b2:	32a8a0ef          	jal	a1adc <xmalloc>
   177b6:	118dba03          	ld	s4,280(s11)
   177ba:	1eadb023          	sd	a0,480(s11)
   177be:	000a4503          	lbu	a0,0(s4)
   177c2:	0e050d63          	beqz	a0,178bc <_ZNK6driver12set_up_specsEv+0xa34>
   177c6:	4a81                	li	s5,0
   177c8:	4b25                	li	s6,9
   177ca:	02000b93          	li	s7,32
   177ce:	4585                	li	a1,1
   177d0:	1582                	slli	a1,a1,0x20
   177d2:	20158c13          	addi	s8,a1,513
   177d6:	300d8913          	addi	s2,s11,768
   177da:	84d2                	mv	s1,s4
   177dc:	a021                	j	177e4 <_ZNK6driver12set_up_specsEv+0x95c>
   177de:	0014c503          	lbu	a0,1(s1)
   177e2:	0485                	addi	s1,s1,1
   177e4:	0a05                	addi	s4,s4,1
   177e6:	ff650ce3          	beq	a0,s6,177de <_ZNK6driver12set_up_specsEv+0x956>
   177ea:	ff750ae3          	beq	a0,s7,177de <_ZNK6driver12set_up_specsEv+0x956>
   177ee:	c579                	beqz	a0,178bc <_ZNK6driver12set_up_specsEv+0xa34>
   177f0:	4c81                	li	s9,0
   177f2:	4d01                	li	s10,0
   177f4:	000a4503          	lbu	a0,0(s4)
   177f8:	0a05                	addi	s4,s4,1
   177fa:	1d7d                	addi	s10,s10,-1
   177fc:	0c85                	addi	s9,s9,1
   177fe:	feabebe3          	bltu	s7,a0,177f4 <_ZNK6driver12set_up_specsEv+0x96c>
   17802:	00ac5533          	srl	a0,s8,a0
   17806:	8905                	andi	a0,a0,1
   17808:	d575                	beqz	a0,177f4 <_ZNK6driver12set_up_specsEv+0x96c>
   1780a:	318db503          	ld	a0,792(s11)
   1780e:	320db583          	ld	a1,800(s11)
   17812:	41a009b3          	neg	s3,s10
   17816:	8d89                	sub	a1,a1,a0
   17818:	0135f863          	bgeu	a1,s3,17828 <_ZNK6driver12set_up_specsEv+0x9a0>
   1781c:	854a                	mv	a0,s2
   1781e:	85ce                	mv	a1,s3
   17820:	498890ef          	jal	a0cb8 <_obstack_newchunk>
   17824:	318db503          	ld	a0,792(s11)
   17828:	85a6                	mv	a1,s1
   1782a:	864e                	mv	a2,s3
   1782c:	c85fc0ef          	jal	144b0 <memcpy@plt>
   17830:	318db503          	ld	a0,792(s11)
   17834:	320db583          	ld	a1,800(s11)
   17838:	41a50533          	sub	a0,a0,s10
   1783c:	30adbc23          	sd	a0,792(s11)
   17840:	00b51863          	bne	a0,a1,17850 <_ZNK6driver12set_up_specsEv+0x9c8>
   17844:	4585                	li	a1,1
   17846:	854a                	mv	a0,s2
   17848:	470890ef          	jal	a0cb8 <_obstack_newchunk>
   1784c:	318db503          	ld	a0,792(s11)
   17850:	00150593          	addi	a1,a0,1
   17854:	30bdbc23          	sd	a1,792(s11)
   17858:	00050023          	sb	zero,0(a0)
   1785c:	310db503          	ld	a0,784(s11)
   17860:	318db583          	ld	a1,792(s11)
   17864:	00a59863          	bne	a1,a0,17874 <_ZNK6driver12set_up_specsEv+0x9ec>
   17868:	350dc603          	lbu	a2,848(s11)
   1786c:	00266613          	ori	a2,a2,2
   17870:	34cd8823          	sb	a2,848(s11)
   17874:	330db683          	ld	a3,816(s11)
   17878:	308db703          	ld	a4,776(s11)
   1787c:	320db603          	ld	a2,800(s11)
   17880:	95b6                	add	a1,a1,a3
   17882:	fff6c693          	not	a3,a3
   17886:	8df5                	and	a1,a1,a3
   17888:	40e586b3          	sub	a3,a1,a4
   1788c:	40e60733          	sub	a4,a2,a4
   17890:	00d76363          	bltu	a4,a3,17896 <_ZNK6driver12set_up_specsEv+0xa0e>
   17894:	862e                	mv	a2,a1
   17896:	1e0db583          	ld	a1,480(s11)
   1789a:	30cdb823          	sd	a2,784(s11)
   1789e:	30cdbc23          	sd	a2,792(s11)
   178a2:	004a9613          	slli	a2,s5,0x4
   178a6:	95b2                	add	a1,a1,a2
   178a8:	e188                	sd	a0,0(a1)
   178aa:	0195a423          	sw	s9,8(a1)
   178ae:	fffa4503          	lbu	a0,-1(s4)
   178b2:	c509                	beqz	a0,178bc <_ZNK6driver12set_up_specsEv+0xa34>
   178b4:	000a4503          	lbu	a0,0(s4)
   178b8:	0a85                	addi	s5,s5,1
   178ba:	f105                	bnez	a0,177da <_ZNK6driver12set_up_specsEv+0x952>
   178bc:	108db583          	ld	a1,264(s11)
   178c0:	4929                	li	s2,10
   178c2:	03b00a93          	li	s5,59
   178c6:	02000993          	li	s3,32
   178ca:	280d8a13          	addi	s4,s11,640
   178ce:	a021                	j	178d6 <_ZNK6driver12set_up_specsEv+0xa4e>
   178d0:	44061863          	bnez	a2,17d20 <_ZNK6driver12set_up_specsEv+0xe98>
   178d4:	0585                	addi	a1,a1,1
   178d6:	0005c503          	lbu	a0,0(a1)
   178da:	ff250de3          	beq	a0,s2,178d4 <_ZNK6driver12set_up_specsEv+0xa4c>
   178de:	cd29                	beqz	a0,17938 <_ZNK6driver12set_up_specsEv+0xab0>
   178e0:	4605                	li	a2,1
   178e2:	a021                	j	178ea <_ZNK6driver12set_up_specsEv+0xa62>
   178e4:	0585                	addi	a1,a1,1
   178e6:	0005c503          	lbu	a0,0(a1)
   178ea:	ff5503e3          	beq	a0,s5,178d0 <_ZNK6driver12set_up_specsEv+0xa48>
   178ee:	46050c63          	beqz	a0,17d66 <_ZNK6driver12set_up_specsEv+0xede>
   178f2:	da6d                	beqz	a2,178e4 <_ZNK6driver12set_up_specsEv+0xa5c>
   178f4:	4601                	li	a2,0
   178f6:	86aa                	mv	a3,a0
   178f8:	84ae                	mv	s1,a1
   178fa:	01350c63          	beq	a0,s3,17912 <_ZNK6driver12set_up_specsEv+0xa8a>
   178fe:	01568a63          	beq	a3,s5,17912 <_ZNK6driver12set_up_specsEv+0xa8a>
   17902:	46068263          	beqz	a3,17d66 <_ZNK6driver12set_up_specsEv+0xede>
   17906:	0014c683          	lbu	a3,1(s1)
   1790a:	0485                	addi	s1,s1,1
   1790c:	0605                	addi	a2,a2,1
   1790e:	ff3698e3          	bne	a3,s3,178fe <_ZNK6driver12set_up_specsEv+0xa76>
   17912:	fdf50513          	addi	a0,a0,-33
   17916:	00153b13          	seqz	s6,a0
   1791a:	95da                	add	a1,a1,s6
   1791c:	4166063b          	subw	a2,a2,s6
   17920:	8552                	mv	a0,s4
   17922:	3d2070ef          	jal	1ecf4 <_ZN10used_arg_tclEPKci>
   17926:	0004c583          	lbu	a1,0(s1)
   1792a:	01654633          	xor	a2,a0,s6
   1792e:	1581                	addi	a1,a1,-32
   17930:	0015b593          	seqz	a1,a1
   17934:	95a6                	add	a1,a1,s1
   17936:	bf45                	j	178e6 <_ZNK6driver12set_up_specsEv+0xa5e>
   17938:	110db583          	ld	a1,272(s11)
   1793c:	0005c603          	lbu	a2,0(a1)
   17940:	0f8db503          	ld	a0,248(s11)
   17944:	c601                	beqz	a2,1794c <_ZNK6driver12set_up_specsEv+0xac4>
   17946:	4601                	li	a2,0
   17948:	6b8870ef          	jal	9f000 <concat>
   1794c:	47a9                	li	a5,10
   1794e:	02000d13          	li	s10,32
   17952:	03b00b93          	li	s7,59
   17956:	597d                	li	s2,-1
   17958:	02095593          	srli	a1,s2,0x20
   1795c:	f2b43423          	sd	a1,-216(s0)
   17960:	4585                	li	a1,1
   17962:	f2b43c23          	sd	a1,-200(s0)
   17966:	4701                	li	a4,0
   17968:	00150c93          	addi	s9,a0,1
   1796c:	fff54693          	not	a3,a0
   17970:	85aa                	mv	a1,a0
   17972:	84aa                	mv	s1,a0
   17974:	00054603          	lbu	a2,0(a0)
   17978:	00f61b63          	bne	a2,a5,1798e <_ZNK6driver12set_up_specsEv+0xb06>
   1797c:	0485                	addi	s1,s1,1
   1797e:	0585                	addi	a1,a1,1
   17980:	0c85                	addi	s9,s9,1
   17982:	16fd                	addi	a3,a3,-1
   17984:	0705                	addi	a4,a4,1
   17986:	0004c603          	lbu	a2,0(s1)
   1798a:	fef609e3          	beq	a2,a5,1797c <_ZNK6driver12set_up_specsEv+0xaf4>
   1798e:	32060b63          	beqz	a2,17cc4 <_ZNK6driver12set_up_specsEv+0xe3c>
   17992:	f2943823          	sd	s1,-208(s0)
   17996:	f4e43423          	sd	a4,-184(s0)
   1799a:	f6d43023          	sd	a3,-160(s0)
   1799e:	f4a43c23          	sd	a0,-168(s0)
   179a2:	f4b43823          	sd	a1,-176(s0)
   179a6:	4981                	li	s3,0
   179a8:	4585                	li	a1,1
   179aa:	0ff67513          	zext.b	a0,a2
   179ae:	01a50d63          	beq	a0,s10,179c8 <_ZNK6driver12set_up_specsEv+0xb40>
   179b2:	3c050663          	beqz	a0,17d7e <_ZNK6driver12set_up_specsEv+0xef6>
   179b6:	000cc603          	lbu	a2,0(s9)
   179ba:	0985                	addi	s3,s3,1
   179bc:	0c85                	addi	s9,s9,1
   179be:	0585                	addi	a1,a1,1
   179c0:	0ff67513          	zext.b	a0,a2
   179c4:	ffa517e3          	bne	a0,s10,179b2 <_ZNK6driver12set_up_specsEv+0xb2a>
   179c8:	f2b43023          	sd	a1,-224(s0)
   179cc:	fff5851b          	addiw	a0,a1,-1
   179d0:	f4a43023          	sd	a0,-192(s0)
   179d4:	4b05                	li	s6,1
   179d6:	4585                	li	a1,1
   179d8:	f7343423          	sd	s3,-152(s0)
   179dc:	a035                	j	17a08 <_ZNK6driver12set_up_specsEv+0xb80>
   179de:	85ce                	mv	a1,s3
   179e0:	001a4db7          	lui	s11,0x1a4
   179e4:	050d8d93          	addi	s11,s11,80 # 1a4050 <_ZL16at_file_supplied>
   179e8:	000ac503          	lbu	a0,0(s5)
   179ec:	0019b613          	seqz	a2,s3
   179f0:	367d                	addiw	a2,a2,-1
   179f2:	f7043b03          	ld	s6,-144(s0)
   179f6:	01667b33          	and	s6,a2,s6
   179fa:	1501                	addi	a0,a0,-32
   179fc:	00153c93          	seqz	s9,a0
   17a00:	9cd6                	add	s9,s9,s5
   17a02:	597d                	li	s2,-1
   17a04:	f6843983          	ld	s3,-152(s0)
   17a08:	000cc503          	lbu	a0,0(s9)
   17a0c:	0b750863          	beq	a0,s7,17abc <_ZNK6driver12set_up_specsEv+0xc34>
   17a10:	36050763          	beqz	a0,17d7e <_ZNK6driver12set_up_specsEv+0xef6>
   17a14:	cdd1                	beqz	a1,17ab0 <_ZNK6driver12set_up_specsEv+0xc28>
   17a16:	4c01                	li	s8,0
   17a18:	020c9593          	slli	a1,s9,0x20
   17a1c:	40b004b3          	neg	s1,a1
   17a20:	85aa                	mv	a1,a0
   17a22:	8ae6                	mv	s5,s9
   17a24:	01a50f63          	beq	a0,s10,17a42 <_ZNK6driver12set_up_specsEv+0xbba>
   17a28:	01758d63          	beq	a1,s7,17a42 <_ZNK6driver12set_up_specsEv+0xbba>
   17a2c:	34058963          	beqz	a1,17d7e <_ZNK6driver12set_up_specsEv+0xef6>
   17a30:	001ac583          	lbu	a1,1(s5)
   17a34:	0a85                	addi	s5,s5,1
   17a36:	02091613          	slli	a2,s2,0x20
   17a3a:	94b2                	add	s1,s1,a2
   17a3c:	3c7d                	addiw	s8,s8,-1
   17a3e:	ffa595e3          	bne	a1,s10,17a28 <_ZNK6driver12set_up_specsEv+0xba0>
   17a42:	f7643823          	sd	s6,-144(s0)
   17a46:	fdf50513          	addi	a0,a0,-33
   17a4a:	418005bb          	negw	a1,s8
   17a4e:	00153913          	seqz	s2,a0
   17a52:	9cca                	add	s9,s9,s2
   17a54:	4125863b          	subw	a2,a1,s2
   17a58:	8552                	mv	a0,s4
   17a5a:	85e6                	mv	a1,s9
   17a5c:	298070ef          	jal	1ecf4 <_ZN10used_arg_tclEPKci>
   17a60:	074dab03          	lw	s6,116(s11)
   17a64:	012549b3          	xor	s3,a0,s2
   17a68:	85ce                	mv	a1,s3
_ZL11default_argPKci():
   17a6a:	f7605fe3          	blez	s6,179e8 <_ZNK6driver12set_up_specsEv+0xb60>
   17a6e:	1e0dbd83          	ld	s11,480(s11)
   17a72:	020c9513          	slli	a0,s9,0x20
   17a76:	409005b3          	neg	a1,s1
   17a7a:	8d89                	sub	a1,a1,a0
   17a7c:	4205d493          	srai	s1,a1,0x20
   17a80:	0da1                	addi	s11,s11,8
   17a82:	a029                	j	17a8c <_ZNK6driver12set_up_specsEv+0xc04>
   17a84:	1b7d                	addi	s6,s6,-1
   17a86:	0dc1                	addi	s11,s11,16
   17a88:	f40b0be3          	beqz	s6,179de <_ZNK6driver12set_up_specsEv+0xb56>
   17a8c:	000da503          	lw	a0,0(s11)
   17a90:	412005bb          	negw	a1,s2
   17a94:	9d89                	subw	a1,a1,a0
   17a96:	ff8597e3          	bne	a1,s8,17a84 <_ZNK6driver12set_up_specsEv+0xbfc>
   17a9a:	ff8db583          	ld	a1,-8(s11)
   17a9e:	8566                	mv	a0,s9
   17aa0:	8626                	mv	a2,s1
   17aa2:	baffc0ef          	jal	14650 <strncmp@plt>
   17aa6:	fd79                	bnez	a0,17a84 <_ZNK6driver12set_up_specsEv+0xbfc>
_ZNK6driver12set_up_specsEv():
   17aa8:	4585                	li	a1,1
   17aaa:	bf1d                	j	179e0 <_ZNK6driver12set_up_specsEv+0xb58>
   17aac:	2c050963          	beqz	a0,17d7e <_ZNK6driver12set_up_specsEv+0xef6>
   17ab0:	001cc503          	lbu	a0,1(s9)
   17ab4:	0c85                	addi	s9,s9,1
   17ab6:	ff751be3          	bne	a0,s7,17aac <_ZNK6driver12set_up_specsEv+0xc24>
   17aba:	a80d                	j	17aec <_ZNK6driver12set_up_specsEv+0xc64>
   17abc:	c985                	beqz	a1,17aec <_ZNK6driver12set_up_specsEv+0xc64>
   17abe:	f3843503          	ld	a0,-200(s0)
   17ac2:	c50d                	beqz	a0,17aec <_ZNK6driver12set_up_specsEv+0xc64>
   17ac4:	f4043483          	ld	s1,-192(s0)
   17ac8:	1482                	slli	s1,s1,0x20
   17aca:	9081                	srli	s1,s1,0x20
   17acc:	f5043c03          	ld	s8,-176(s0)
   17ad0:	4505                	li	a0,1
   17ad2:	02a49063          	bne	s1,a0,17af2 <_ZNK6driver12set_up_specsEv+0xc6a>
   17ad6:	f3043503          	ld	a0,-208(s0)
   17ada:	00054503          	lbu	a0,0(a0)
   17ade:	02e00593          	li	a1,46
   17ae2:	00b51863          	bne	a0,a1,17af2 <_ZNK6driver12set_up_specsEv+0xc6a>
   17ae6:	f2043c23          	sd	zero,-200(s0)
   17aea:	a081                	j	17b2a <_ZNK6driver12set_up_specsEv+0xca2>
   17aec:	f5043c03          	ld	s8,-176(s0)
   17af0:	a82d                	j	17b2a <_ZNK6driver12set_up_specsEv+0xca2>
   17af2:	f2843503          	ld	a0,-216(s0)
   17af6:	f2043583          	ld	a1,-224(s0)
   17afa:	8d6d                	and	a0,a0,a1
   17afc:	7e1890ef          	jal	a1adc <xmalloc>
   17b00:	8aaa                	mv	s5,a0
   17b02:	f3043583          	ld	a1,-208(s0)
   17b06:	8626                	mv	a2,s1
   17b08:	ae8fc0ef          	jal	13df0 <strncpy@plt>
   17b0c:	94d6                	add	s1,s1,s5
   17b0e:	00048023          	sb	zero,0(s1)
   17b12:	03a00593          	li	a1,58
   17b16:	8556                	mv	a0,s5
   17b18:	a19fc0ef          	jal	14530 <strchr@plt>
   17b1c:	c119                	beqz	a0,17b22 <_ZNK6driver12set_up_specsEv+0xc9a>
   17b1e:	00050023          	sb	zero,0(a0)
   17b22:	f2043c23          	sd	zero,-200(s0)
   17b26:	195db823          	sd	s5,400(s11)
   17b2a:	03a00793          	li	a5,58
   17b2e:	f5843703          	ld	a4,-168(s0)
   17b32:	f4843803          	ld	a6,-184(s0)
   17b36:	020b0f63          	beqz	s6,17b74 <_ZNK6driver12set_up_specsEv+0xcec>
   17b3a:	f4043503          	ld	a0,-192(s0)
   17b3e:	c91d                	beqz	a0,17b74 <_ZNK6driver12set_up_specsEv+0xcec>
   17b40:	02099513          	slli	a0,s3,0x20
   17b44:	02055a93          	srli	s5,a0,0x20
   17b48:	f3043503          	ld	a0,-208(s0)
   17b4c:	9556                	add	a0,a0,s5
   17b4e:	fffa8593          	addi	a1,s5,-1
   17b52:	01070633          	add	a2,a4,a6
   17b56:	00064683          	lbu	a3,0(a2)
   17b5a:	06f68f63          	beq	a3,a5,17bd8 <_ZNK6driver12set_up_specsEv+0xd50>
   17b5e:	15fd                	addi	a1,a1,-1
   17b60:	0805                	addi	a6,a6,1
   17b62:	01070633          	add	a2,a4,a6
   17b66:	f6043683          	ld	a3,-160(s0)
   17b6a:	16fd                	addi	a3,a3,-1
   17b6c:	f6d43023          	sd	a3,-160(s0)
   17b70:	fea661e3          	bltu	a2,a0,17b52 <_ZNK6driver12set_up_specsEv+0xcca>
   17b74:	001c8513          	addi	a0,s9,1
   17b78:	47a9                	li	a5,10
   17b7a:	b3f5                	j	17966 <_ZNK6driver12set_up_specsEv+0xade>
_ZNK3vecIPKc7va_heap6vl_ptrE6lengthEv():
   17b7c:	0c8db503          	ld	a0,200(s11)
   17b80:	e0050963          	beqz	a0,17192 <_ZNK6driver12set_up_specsEv+0x30a>
_ZNK3vecIPKc7va_heap8vl_embedE6lengthEv():
   17b84:	414c                	lw	a1,4(a0)
   17b86:	4609                	li	a2,2
_ZNK6driver12set_up_specsEv():
   17b88:	06c5ef63          	bltu	a1,a2,17c06 <_ZNK6driver12set_up_specsEv+0xd7e>
   17b8c:	000a3537          	lui	a0,0xa3
   17b90:	3dc50513          	addi	a0,a0,988 # a33dc <_ZL12thread_model+0x127>
   17b94:	090360ef          	jal	4dc24 <_Z5errorPKcz>
   17b98:	dfaff06f          	j	17192 <_ZNK6driver12set_up_specsEv+0x30a>
_ZNK3vecIPKc7va_heap6vl_ptrE6lengthEv():
   17b9c:	0c8db503          	ld	a0,200(s11)
   17ba0:	f0050e63          	beqz	a0,172bc <_ZNK6driver12set_up_specsEv+0x434>
_ZNK3vecIPKc7va_heap8vl_embedE6lengthEv():
   17ba4:	414c                	lw	a1,4(a0)
   17ba6:	4609                	li	a2,2
_ZNK6driver12set_up_specsEv():
   17ba8:	06c5e963          	bltu	a1,a2,17c1a <_ZNK6driver12set_up_specsEv+0xd92>
   17bac:	000a3537          	lui	a0,0xa3
   17bb0:	42d50513          	addi	a0,a0,1069 # a342d <_ZL12thread_model+0x178>
   17bb4:	070360ef          	jal	4dc24 <_Z5errorPKcz>
   17bb8:	f04ff06f          	j	172bc <_ZNK6driver12set_up_specsEv+0x434>
_ZN3vecIPKc7va_heap6vl_ptrE7addressEv():
   17bbc:	0c8db503          	ld	a0,200(s11)
   17bc0:	00153593          	seqz	a1,a0
   17bc4:	00850a93          	addi	s5,a0,8
   17bc8:	15fd                	addi	a1,a1,-1
   17bca:	0155f4b3          	and	s1,a1,s5
_ZNK3vecIPKc7va_heap6vl_ptrE6lengthEv():
   17bce:	16050a63          	beqz	a0,17d42 <_ZNK6driver12set_up_specsEv+0xeba>
_ZNK3vecIPKc7va_heap8vl_embedE6lengthEv():
   17bd2:	00456503          	lwu	a0,4(a0)
   17bd6:	a2bd                	j	17d44 <_ZNK6driver12set_up_specsEv+0xebc>
_ZNK6driver12set_up_specsEv():
   17bd8:	00160a13          	addi	s4,a2,1
   17bdc:	04aa7963          	bgeu	s4,a0,17c2e <_ZNK6driver12set_up_specsEv+0xda6>
   17be0:	f3043603          	ld	a2,-208(s0)
   17be4:	9656                	add	a2,a2,s5
   17be6:	03a00693          	li	a3,58
   17bea:	84d2                	mv	s1,s4
   17bec:	0004c703          	lbu	a4,0(s1)
   17bf0:	fc670793          	addi	a5,a4,-58
   17bf4:	0017b993          	seqz	s3,a5
   17bf8:	02d70d63          	beq	a4,a3,17c32 <_ZNK6driver12set_up_specsEv+0xdaa>
   17bfc:	15fd                	addi	a1,a1,-1
   17bfe:	0485                	addi	s1,s1,1
   17c00:	f5f5                	bnez	a1,17bec <_ZNK6driver12set_up_specsEv+0xd64>
   17c02:	84b2                	mv	s1,a2
   17c04:	a03d                	j	17c32 <_ZNK6driver12set_up_specsEv+0xdaa>
   17c06:	4605                	li	a2,1
   17c08:	d8c59563          	bne	a1,a2,17192 <_ZNK6driver12set_up_specsEv+0x30a>
   17c0c:	6508                	ld	a0,8(a0)
   17c0e:	795890ef          	jal	a1ba2 <xstrdup>
   17c12:	12adbc23          	sd	a0,312(s11)
   17c16:	d7cff06f          	j	17192 <_ZNK6driver12set_up_specsEv+0x30a>
   17c1a:	4605                	li	a2,1
   17c1c:	eac59063          	bne	a1,a2,172bc <_ZNK6driver12set_up_specsEv+0x434>
   17c20:	6508                	ld	a0,8(a0)
   17c22:	781890ef          	jal	a1ba2 <xstrdup>
   17c26:	14adb423          	sd	a0,328(s11)
   17c2a:	e92ff06f          	j	172bc <_ZNK6driver12set_up_specsEv+0x434>
   17c2e:	4981                	li	s3,0
   17c30:	84d2                	mv	s1,s4
   17c32:	0004c583          	lbu	a1,0(s1)
   17c36:	03a00613          	li	a2,58
   17c3a:	8b26                	mv	s6,s1
   17c3c:	00c58363          	beq	a1,a2,17c42 <_ZNK6driver12set_up_specsEv+0xdba>
   17c40:	8b2a                	mv	s6,a0
   17c42:	f5843503          	ld	a0,-168(s0)
   17c46:	40ab0bb3          	sub	s7,s6,a0
   17c4a:	fffb8513          	addi	a0,s7,-1
   17c4e:	01051d63          	bne	a0,a6,17c68 <_ZNK6driver12set_up_specsEv+0xde0>
   17c52:	000ca537          	lui	a0,0xca
   17c56:	3cd50513          	addi	a0,a0,973 # ca3cd <_ZZL9init_specvE2tf+0x24e39>
   17c5a:	749890ef          	jal	a1ba2 <xstrdup>
   17c5e:	1aadb023          	sd	a0,416(s11)
   17c62:	02099963          	bnez	s3,17c94 <_ZNK6driver12set_up_specsEv+0xe0c>
   17c66:	a8b9                	j	17cc4 <_ZNK6driver12set_up_specsEv+0xe3c>
   17c68:	8cc2                	mv	s9,a6
   17c6a:	410b8533          	sub	a0,s7,a6
   17c6e:	66f890ef          	jal	a1adc <xmalloc>
   17c72:	892a                	mv	s2,a0
   17c74:	fffcc613          	not	a2,s9
   17c78:	965e                	add	a2,a2,s7
   17c7a:	85d2                	mv	a1,s4
   17c7c:	835fc0ef          	jal	144b0 <memcpy@plt>
   17c80:	f6043583          	ld	a1,-160(s0)
   17c84:	9b2e                	add	s6,s6,a1
   17c86:	9b4a                	add	s6,s6,s2
   17c88:	000b0023          	sb	zero,0(s6)
   17c8c:	1b2db023          	sd	s2,416(s11)
   17c90:	02098a63          	beqz	s3,17cc4 <_ZNK6driver12set_up_specsEv+0xe3c>
   17c94:	0004c503          	lbu	a0,0(s1)
   17c98:	03a00593          	li	a1,58
   17c9c:	02b51463          	bne	a0,a1,17cc4 <_ZNK6driver12set_up_specsEv+0xe3c>
   17ca0:	409a8933          	sub	s2,s5,s1
   17ca4:	9962                	add	s2,s2,s8
   17ca6:	854a                	mv	a0,s2
   17ca8:	635890ef          	jal	a1adc <xmalloc>
   17cac:	89aa                	mv	s3,a0
   17cae:	00148593          	addi	a1,s1,1
   17cb2:	fff90613          	addi	a2,s2,-1
   17cb6:	ffafc0ef          	jal	144b0 <memcpy@plt>
   17cba:	994e                	add	s2,s2,s3
   17cbc:	fe090fa3          	sb	zero,-1(s2)
   17cc0:	193dbc23          	sd	s3,408(s11)
   17cc4:	001a4737          	lui	a4,0x1a4
   17cc8:	054da583          	lw	a1,84(s11)
   17ccc:	178db503          	ld	a0,376(s11)
   17cd0:	190db603          	ld	a2,400(s11)
   17cd4:	118db683          	ld	a3,280(s11)
   17cd8:	fc073483          	ld	s1,-64(a4) # 1a3fc0 <targetm_common+0x38>
   17cdc:	0f8db703          	ld	a4,248(s11)
   17ce0:	100db783          	ld	a5,256(s11)
   17ce4:	108db803          	ld	a6,264(s11)
   17ce8:	110db883          	ld	a7,272(s11)
   17cec:	9482                	jalr	s1
   17cee:	1a0db583          	ld	a1,416(s11)
   17cf2:	18adb823          	sd	a0,400(s11)
   17cf6:	e10d                	bnez	a0,17d18 <_ZNK6driver12set_up_specsEv+0xe90>
   17cf8:	c185                	beqz	a1,17d18 <_ZNK6driver12set_up_specsEv+0xe90>
   17cfa:	0005c603          	lbu	a2,0(a1)
   17cfe:	02e00693          	li	a3,46
   17d02:	00d61f63          	bne	a2,a3,17d20 <_ZNK6driver12set_up_specsEv+0xe98>
   17d06:	0015c603          	lbu	a2,1(a1)
   17d0a:	ea19                	bnez	a2,17d20 <_ZNK6driver12set_up_specsEv+0xe98>
   17d0c:	84aa                	mv	s1,a0
   17d0e:	852e                	mv	a0,a1
   17d10:	f50fc0ef          	jal	14460 <free@plt>
   17d14:	8526                	mv	a0,s1
   17d16:	a019                	j	17d1c <_ZNK6driver12set_up_specsEv+0xe94>
   17d18:	c501                	beqz	a0,17d20 <_ZNK6driver12set_up_specsEv+0xe98>
   17d1a:	e199                	bnez	a1,17d20 <_ZNK6driver12set_up_specsEv+0xe98>
   17d1c:	1aadb023          	sd	a0,416(s11)
   17d20:	f2040113          	addi	sp,s0,-224
   17d24:	60ee                	ld	ra,216(sp)
   17d26:	644e                	ld	s0,208(sp)
   17d28:	64ae                	ld	s1,200(sp)
   17d2a:	690e                	ld	s2,192(sp)
   17d2c:	79ea                	ld	s3,184(sp)
   17d2e:	7a4a                	ld	s4,176(sp)
   17d30:	7aaa                	ld	s5,168(sp)
   17d32:	7b0a                	ld	s6,160(sp)
   17d34:	6bea                	ld	s7,152(sp)
   17d36:	6c4a                	ld	s8,144(sp)
   17d38:	6caa                	ld	s9,136(sp)
   17d3a:	6d0a                	ld	s10,128(sp)
   17d3c:	7de6                	ld	s11,120(sp)
   17d3e:	612d                	addi	sp,sp,224
   17d40:	8082                	ret
   17d42:	4a81                	li	s5,0
   17d44:	050e                	slli	a0,a0,0x3
   17d46:	9aaa                	add	s5,s5,a0
   17d48:	eb548f63          	beq	s1,s5,17406 <_ZNK6driver12set_up_specsEv+0x57e>
   17d4c:	000a39b7          	lui	s3,0xa3
   17d50:	47598993          	addi	s3,s3,1141 # a3475 <_ZL12thread_model+0x1c0>
   17d54:	6088                	ld	a0,0(s1)
   17d56:	85ce                	mv	a1,s3
   17d58:	5d0060ef          	jal	1e328 <_ZL20add_sysrooted_prefixP11path_prefixPKcS2_iii>
   17d5c:	04a1                	addi	s1,s1,8
   17d5e:	ff549be3          	bne	s1,s5,17d54 <_ZNK6driver12set_up_specsEv+0xecc>
   17d62:	ea4ff06f          	j	17406 <_ZNK6driver12set_up_specsEv+0x57e>
   17d66:	001a8537          	lui	a0,0x1a8
   17d6a:	9e053503          	ld	a0,-1568(a0) # 1a79e0 <input_location>
   17d6e:	108db603          	ld	a2,264(s11)
   17d72:	000a85b7          	lui	a1,0xa8
   17d76:	e0658593          	addi	a1,a1,-506 # a7e06 <_ZZL9init_specvE2tf+0x2872>
   17d7a:	1dc360ef          	jal	4df56 <_Z11fatal_errormPKcz>
   17d7e:	001a8537          	lui	a0,0x1a8
   17d82:	9e053503          	ld	a0,-1568(a0) # 1a79e0 <input_location>
   17d86:	0f8db603          	ld	a2,248(s11)
   17d8a:	110db683          	ld	a3,272(s11)
   17d8e:	000a85b7          	lui	a1,0xa8
   17d92:	e2958593          	addi	a1,a1,-471 # a7e29 <_ZZL9init_specvE2tf+0x2895>
   17d96:	1c0360ef          	jal	4df56 <_Z11fatal_errormPKcz>

000000000006a9c8 <_ZL19destringize_and_runP10cpp_readerPK10cpp_stringm>:
_ZL19destringize_and_runP10cpp_readerPK10cpp_stringm():
   6a9c8:	7159                	addi	sp,sp,-112
   6a9ca:	f486                	sd	ra,104(sp)
   6a9cc:	f0a2                	sd	s0,96(sp)
   6a9ce:	eca6                	sd	s1,88(sp)
   6a9d0:	e8ca                	sd	s2,80(sp)
   6a9d2:	e4ce                	sd	s3,72(sp)
   6a9d4:	e0d2                	sd	s4,64(sp)
   6a9d6:	fc56                	sd	s5,56(sp)
   6a9d8:	f85a                	sd	s6,48(sp)
   6a9da:	f45e                	sd	s7,40(sp)
   6a9dc:	f062                	sd	s8,32(sp)
   6a9de:	ec66                	sd	s9,24(sp)
   6a9e0:	e86a                	sd	s10,16(sp)
   6a9e2:	e46e                	sd	s11,8(sp)
   6a9e4:	1880                	addi	s0,sp,112
   6a9e6:	8932                	mv	s2,a2
   6a9e8:	89aa                	mv	s3,a0
   6a9ea:	0005e503          	lwu	a0,0(a1)
   6a9ee:	fff50613          	addi	a2,a0,-1
   6a9f2:	02061513          	slli	a0,a2,0x20
   6a9f6:	9101                	srli	a0,a0,0x20
   6a9f8:	053d                	addi	a0,a0,15
   6a9fa:	9941                	andi	a0,a0,-16
   6a9fc:	40a10a33          	sub	s4,sp,a0
   6aa00:	8152                	mv	sp,s4
   6aa02:	658c                	ld	a1,8(a1)
   6aa04:	0005c503          	lbu	a0,0(a1)
   6aa08:	fb450513          	addi	a0,a0,-76
   6aa0c:	00153513          	seqz	a0,a0
   6aa10:	952e                	add	a0,a0,a1
   6aa12:	0505                	addi	a0,a0,1
   6aa14:	95b2                	add	a1,a1,a2
   6aa16:	84d2                	mv	s1,s4
   6aa18:	04b57063          	bgeu	a0,a1,6aa58 <_ZL19destringize_and_runP10cpp_readerPK10cpp_stringm+0x90>
   6aa1c:	05c00613          	li	a2,92
   6aa20:	02200693          	li	a3,34
   6aa24:	8752                	mv	a4,s4
   6aa26:	a811                	j	6aa3a <_ZL19destringize_and_runP10cpp_readerPK10cpp_stringm+0x72>
   6aa28:	0505                	addi	a0,a0,1
   6aa2a:	0505                	addi	a0,a0,1
   6aa2c:	00170493          	addi	s1,a4,1
   6aa30:	00f70023          	sb	a5,0(a4)
   6aa34:	8726                	mv	a4,s1
   6aa36:	02b57163          	bgeu	a0,a1,6aa58 <_ZL19destringize_and_runP10cpp_readerPK10cpp_stringm+0x90>
   6aa3a:	00054783          	lbu	a5,0(a0)
   6aa3e:	fec796e3          	bne	a5,a2,6aa2a <_ZL19destringize_and_runP10cpp_readerPK10cpp_stringm+0x62>
   6aa42:	00154783          	lbu	a5,1(a0)
   6aa46:	05c00493          	li	s1,92
   6aa4a:	fc978fe3          	beq	a5,s1,6aa28 <_ZL19destringize_and_runP10cpp_readerPK10cpp_stringm+0x60>
   6aa4e:	fcd78de3          	beq	a5,a3,6aa28 <_ZL19destringize_and_runP10cpp_readerPK10cpp_stringm+0x60>
   6aa52:	05c00793          	li	a5,92
   6aa56:	bfd1                	j	6aa2a <_ZL19destringize_and_runP10cpp_readerPK10cpp_stringm+0x62>
   6aa58:	0889b503          	ld	a0,136(s3)
   6aa5c:	f8a43823          	sd	a0,-112(s0)
   6aa60:	1e89bb03          	ld	s6,488(s3)
   6aa64:	2109bb83          	ld	s7,528(s3)
   6aa68:	4529                	li	a0,10
   6aa6a:	00a48023          	sb	a0,0(s1)
   6aa6e:	4505                	li	a0,1
   6aa70:	03800593          	li	a1,56
   6aa74:	08a370ef          	jal	a1afe <xcalloc>
   6aa78:	3d09b583          	ld	a1,976(s3)
   6aa7c:	3d89b603          	ld	a2,984(s3)
   6aa80:	8e0d                	sub	a2,a2,a1
   6aa82:	0d700693          	li	a3,215
   6aa86:	08a9b423          	sd	a0,136(s3)
   6aa8a:	00c6ea63          	bltu	a3,a2,6aa9e <_ZL19destringize_and_runP10cpp_readerPK10cpp_stringm+0xd6>
   6aa8e:	3b898513          	addi	a0,s3,952
   6aa92:	0d800593          	li	a1,216
   6aa96:	222360ef          	jal	a0cb8 <_obstack_newchunk>
   6aa9a:	3d09b583          	ld	a1,976(s3)
   6aa9e:	3c89ba83          	ld	s5,968(s3)
   6aaa2:	0d858513          	addi	a0,a1,216
   6aaa6:	01551863          	bne	a0,s5,6aab6 <_ZL19destringize_and_runP10cpp_readerPK10cpp_stringm+0xee>
   6aaaa:	4089c583          	lbu	a1,1032(s3)
   6aaae:	0025e593          	ori	a1,a1,2
   6aab2:	40b98423          	sb	a1,1032(s3)
   6aab6:	3e89b603          	ld	a2,1000(s3)
   6aaba:	3c09b683          	ld	a3,960(s3)
   6aabe:	3d89b583          	ld	a1,984(s3)
   6aac2:	414484b3          	sub	s1,s1,s4
   6aac6:	9532                	add	a0,a0,a2
   6aac8:	fff64613          	not	a2,a2
   6aacc:	8d71                	and	a0,a0,a2
   6aace:	40d50633          	sub	a2,a0,a3
   6aad2:	40d586b3          	sub	a3,a1,a3
   6aad6:	3ca9b823          	sd	a0,976(s3)
   6aada:	00c6f563          	bgeu	a3,a2,6aae4 <_ZL19destringize_and_runP10cpp_readerPK10cpp_stringm+0x11c>
   6aade:	3cb9b823          	sd	a1,976(s3)
   6aae2:	852e                	mv	a0,a1
   6aae4:	3ca9b423          	sd	a0,968(s3)
   6aae8:	0d800613          	li	a2,216
   6aaec:	8556                	mv	a0,s5
   6aaee:	4581                	li	a1,0
   6aaf0:	a21a90ef          	jal	14510 <memset@plt>
   6aaf4:	94d2                	add	s1,s1,s4
   6aaf6:	4511                	li	a0,4
   6aaf8:	06aa8423          	sb	a0,104(s5)
   6aafc:	0009b503          	ld	a0,0(s3)
   6ab00:	4595                	li	a1,5
   6ab02:	05600613          	li	a2,86
   6ab06:	06ba8423          	sb	a1,104(s5)
   6ab0a:	692c                	ld	a1,80(a0)
   6ab0c:	06954683          	lbu	a3,105(a0)
   6ab10:	014ab823          	sd	s4,16(s5)
   6ab14:	014abc23          	sd	s4,24(s5)
   6ab18:	029ab023          	sd	s1,32(s5)
   6ab1c:	04aab423          	sd	a0,72(s5)
   6ab20:	6a89bc03          	ld	s8,1704(s3)
   6ab24:	04bab823          	sd	a1,80(s5)
   6ab28:	06da84a3          	sb	a3,105(s5)
   6ab2c:	0289b503          	ld	a0,40(s3)
   6ab30:	6b29b423          	sd	s2,1704(s3)
   6ab34:	0ac98023          	sb	a2,160(s3)
   6ab38:	4a05                	li	s4,1
   6ab3a:	6928                	ld	a0,80(a0)
   6ab3c:	0159b023          	sd	s5,0(s3)
   6ab40:	01498823          	sb	s4,16(s3)
   6ab44:	00098aa3          	sb	zero,21(s3)
   6ab48:	02a9b823          	sd	a0,48(s3)
   6ab4c:	854e                	mv	a0,s3
   6ab4e:	4f6090ef          	jal	74044 <_cpp_clean_line>
   6ab52:	0909b483          	ld	s1,144(s3)
   6ab56:	00137517          	auipc	a0,0x137
   6ab5a:	a5a50513          	addi	a0,a0,-1446 # 1a15b0 <_ZL6dtable+0x138>
   6ab5e:	08a9b823          	sd	a0,144(s3)
   6ab62:	854e                	mv	a0,s3
   6ab64:	424010ef          	jal	6bf88 <_ZL9do_pragmaP10cpp_reader>
   6ab68:	0a09c503          	lbu	a0,160(s3)
   6ab6c:	05400a93          	li	s5,84
   6ab70:	01551963          	bne	a0,s5,6ab82 <_ZL19destringize_and_runP10cpp_readerPK10cpp_stringm+0x1ba>
   6ab74:	0a299503          	lh	a0,162(s3)
   6ab78:	0a2e                	slli	s4,s4,0xb
   6ab7a:	01456533          	or	a0,a0,s4
   6ab7e:	0aa99123          	sh	a0,162(s3)
   6ab82:	4585                	li	a1,1
   6ab84:	4c85                	li	s9,1
   6ab86:	854e                	mv	a0,s3
   6ab88:	a67fe0ef          	jal	695ee <_ZL13end_directiveP10cpp_readeri>
   6ab8c:	0a09c503          	lbu	a0,160(s3)
   6ab90:	0899b823          	sd	s1,144(s3)
   6ab94:	09551a63          	bne	a0,s5,6ac28 <_ZL19destringize_and_runP10cpp_readerPK10cpp_stringm+0x260>
   6ab98:	09898a93          	addi	s5,s3,152
   6ab9c:	64000513          	li	a0,1600
   6aba0:	73d360ef          	jal	a1adc <xmalloc>
   6aba4:	8a2a                	mv	s4,a0
   6aba6:	4481                	li	s1,0
   6aba8:	cd927057          	vsetivli	zero,4,e64,m2,ta,ma
   6abac:	020af407          	vle64.v	v8,(s5)
   6abb0:	03200d13          	li	s10,50
   6abb4:	4c85                	li	s9,1
   6abb6:	05500d93          	li	s11,85
   6abba:	02057427          	vse64.v	v8,(a0)
   6abbe:	01253023          	sd	s2,0(a0)
   6abc2:	4a85                	li	s5,1
   6abc4:	a835                	j	6ac00 <_ZL19destringize_and_runP10cpp_readerPK10cpp_stringm+0x238>
   6abc6:	854e                	mv	a0,s3
   6abc8:	464130ef          	jal	7e02c <_Z13cpp_get_tokenP10cpp_reader>
   6abcc:	cd927057          	vsetivli	zero,4,e64,m2,ta,ma
   6abd0:	02057407          	vle64.v	v8,(a0)
   6abd4:	009a0533          	add	a0,s4,s1
   6abd8:	02050593          	addi	a1,a0,32
   6abdc:	0205f427          	vse64.v	v8,(a1)
   6abe0:	02a51583          	lh	a1,42(a0)
   6abe4:	02854603          	lbu	a2,40(a0)
   6abe8:	0a85                	addi	s5,s5,1
   6abea:	02048493          	addi	s1,s1,32
   6abee:	4005e593          	ori	a1,a1,1024
   6abf2:	03253023          	sd	s2,32(a0)
   6abf6:	02b51523          	sh	a1,42(a0)
   6abfa:	2c85                	addiw	s9,s9,1
   6abfc:	05b60063          	beq	a2,s11,6ac3c <_ZL19destringize_and_runP10cpp_readerPK10cpp_stringm+0x274>
   6ac00:	020d1513          	slli	a0,s10,0x20
   6ac04:	9101                	srli	a0,a0,0x20
   6ac06:	fcaa90e3          	bne	s5,a0,6abc6 <_ZL19destringize_and_runP10cpp_readerPK10cpp_stringm+0x1fe>
   6ac0a:	001d1513          	slli	a0,s10,0x1
   6ac0e:	956a                	add	a0,a0,s10
   6ac10:	01f5559b          	srliw	a1,a0,0x1f
   6ac14:	952e                	add	a0,a0,a1
   6ac16:	40155d1b          	sraiw	s10,a0,0x1
   6ac1a:	005d1593          	slli	a1,s10,0x5
   6ac1e:	8552                	mv	a0,s4
   6ac20:	717360ef          	jal	a1b36 <xrealloc>
   6ac24:	8a2a                	mv	s4,a0
   6ac26:	b745                	j	6abc6 <_ZL19destringize_and_runP10cpp_readerPK10cpp_stringm+0x1fe>
   6ac28:	4189b683          	ld	a3,1048(s3)
   6ac2c:	31898a13          	addi	s4,s3,792
   6ac30:	c691                	beqz	a3,6ac3c <_ZL19destringize_and_runP10cpp_readerPK10cpp_stringm+0x274>
   6ac32:	1e89b583          	ld	a1,488(s3)
   6ac36:	854e                	mv	a0,s3
   6ac38:	4601                	li	a2,0
   6ac3a:	9682                	jalr	a3
   6ac3c:	0009b503          	ld	a0,0(s3)
   6ac40:	652c                	ld	a1,72(a0)
   6ac42:	06954603          	lbu	a2,105(a0)
   6ac46:	04053823          	sd	zero,80(a0)
   6ac4a:	06c584a3          	sb	a2,105(a1)
   6ac4e:	854e                	mv	a0,s3
   6ac50:	7a8000ef          	jal	6b3f8 <_cpp_pop_buffer>
   6ac54:	0889b503          	ld	a0,136(s3)
   6ac58:	6b89b423          	sd	s8,1704(s3)
   6ac5c:	805a90ef          	jal	14460 <free@plt>
   6ac60:	f9043503          	ld	a0,-112(s0)
   6ac64:	08a9b423          	sd	a0,136(s3)
   6ac68:	1f69b423          	sd	s6,488(s3)
   6ac6c:	2179b823          	sd	s7,528(s3)
   6ac70:	854e                	mv	a0,s3
   6ac72:	4581                	li	a1,0
   6ac74:	8652                	mv	a2,s4
   6ac76:	86e6                	mv	a3,s9
   6ac78:	36f130ef          	jal	7e7e6 <_cpp_push_token_context>
   6ac7c:	f9040113          	addi	sp,s0,-112
   6ac80:	70a6                	ld	ra,104(sp)
   6ac82:	7406                	ld	s0,96(sp)
   6ac84:	64e6                	ld	s1,88(sp)
   6ac86:	6946                	ld	s2,80(sp)
   6ac88:	69a6                	ld	s3,72(sp)
   6ac8a:	6a06                	ld	s4,64(sp)
   6ac8c:	7ae2                	ld	s5,56(sp)
   6ac8e:	7b42                	ld	s6,48(sp)
   6ac90:	7ba2                	ld	s7,40(sp)
   6ac92:	7c02                	ld	s8,32(sp)
   6ac94:	6ce2                	ld	s9,24(sp)
   6ac96:	6d42                	ld	s10,16(sp)
   6ac98:	6da2                	ld	s11,8(sp)
   6ac9a:	6165                	addi	sp,sp,112
   6ac9c:	8082                	ret

0000000000021c5e <_ZL13close_at_filev>:
_ZL13close_at_filev():
   21c5e:	711d                	addi	sp,sp,-96
   21c60:	ec86                	sd	ra,88(sp)
   21c62:	e8a2                	sd	s0,80(sp)
   21c64:	e4a6                	sd	s1,72(sp)
   21c66:	e0ca                	sd	s2,64(sp)
   21c68:	fc4e                	sd	s3,56(sp)
   21c6a:	f852                	sd	s4,48(sp)
   21c6c:	f456                	sd	s5,40(sp)
   21c6e:	f05a                	sd	s6,32(sp)
   21c70:	1080                	addi	s0,sp,96
   21c72:	001a4ab7          	lui	s5,0x1a4
   21c76:	050a8a93          	addi	s5,s5,80 # 1a4050 <_ZL16at_file_supplied>
   21c7a:	029ac503          	lbu	a0,41(s5)
   21c7e:	1a050363          	beqz	a0,21e24 <_ZL13close_at_filev+0x1c6>
   21c82:	238ab503          	ld	a0,568(s5)
   21c86:	020a84a3          	sb	zero,41(s5)
   21c8a:	14050563          	beqz	a0,21dd4 <_ZL13close_at_filev+0x176>
_ZNK3vecIPKc7va_heap8vl_embedE6lengthEv():
   21c8e:	00456b03          	lwu	s6,4(a0)
_ZL13close_at_filev():
   21c92:	140b0163          	beqz	s6,21dd4 <_ZL13close_at_filev+0x176>
   21c96:	001b0513          	addi	a0,s6,1
   21c9a:	1502                	slli	a0,a0,0x20
   21c9c:	8175                	srli	a0,a0,0x1d
   21c9e:	053d                	addi	a0,a0,15
   21ca0:	9941                	andi	a0,a0,-16
   21ca2:	40a10a33          	sub	s4,sp,a0
   21ca6:	8152                	mv	sp,s4
_ZL12make_at_filev():
   21ca8:	05caa503          	lw	a0,92(s5)
   21cac:	c125                	beqz	a0,21d0c <_ZL13close_at_filev+0xae>
   21cae:	1e8ab483          	ld	s1,488(s5)
   21cb2:	c481                	beqz	s1,21cba <_ZL13close_at_filev+0x5c>
   21cb4:	0004c503          	lbu	a0,0(s1)
   21cb8:	e919                	bnez	a0,21cce <_ZL13close_at_filev+0x70>
   21cba:	1c0ab483          	ld	s1,448(s5)
   21cbe:	c481                	beqz	s1,21cc6 <_ZL13close_at_filev+0x68>
   21cc0:	0004c503          	lbu	a0,0(s1)
   21cc4:	e509                	bnez	a0,21cce <_ZL13close_at_filev+0x70>
   21cc6:	000e44b7          	lui	s1,0xe4
   21cca:	96948493          	addi	s1,s1,-1687 # e3969 <_ZZ13trim_filenamePKcE9this_file+0x44f>
   21cce:	090aa603          	lw	a2,144(s5)
   21cd2:	00160513          	addi	a0,a2,1
   21cd6:	08aaa823          	sw	a0,144(s5)
   21cda:	000a65b7          	lui	a1,0xa6
   21cde:	10a58593          	addi	a1,a1,266 # a610a <_ZZL9init_specvE2tf+0xb76>
   21ce2:	fa840513          	addi	a0,s0,-88
   21ce6:	fa840913          	addi	s2,s0,-88
   21cea:	b27f20ef          	jal	14810 <sprintf@plt>
   21cee:	1c0ab503          	ld	a0,448(s5)
   21cf2:	012ac583          	lbu	a1,18(s5)
   21cf6:	8d25                	xor	a0,a0,s1
   21cf8:	00153513          	seqz	a0,a0
   21cfc:	8d6d                	and	a0,a0,a1
   21cfe:	00a905b3          	add	a1,s2,a0
   21d02:	8526                	mv	a0,s1
   21d04:	4601                	li	a2,0
   21d06:	2fa7d0ef          	jal	9f000 <concat>
   21d0a:	a039                	j	21d18 <_ZL13close_at_filev+0xba>
   21d0c:	000e5537          	lui	a0,0xe5
   21d10:	f5e50513          	addi	a0,a0,-162 # e4f5e <_ZZ13trim_filenamePKcE9this_file+0x1a44>
   21d14:	6a57e0ef          	jal	a0bb8 <make_temp_file>
   21d18:	892a                	mv	s2,a0
_ZL13close_at_filev():
   21d1a:	000e5537          	lui	a0,0xe5
   21d1e:	8c750513          	addi	a0,a0,-1849 # e48c7 <_ZZ13trim_filenamePKcE9this_file+0x13ad>
   21d22:	85ca                	mv	a1,s2
   21d24:	4601                	li	a2,0
   21d26:	2da7d0ef          	jal	9f000 <concat>
   21d2a:	89aa                	mv	s3,a0
   21d2c:	000ba5b7          	lui	a1,0xba
   21d30:	a4558593          	addi	a1,a1,-1467 # b9a45 <_ZZL9init_specvE2tf+0x144b1>
   21d34:	854a                	mv	a0,s2
   21d36:	97af20ef          	jal	13eb0 <fopen@plt>
   21d3a:	84aa                	mv	s1,a0
   21d3c:	c22026f3          	csrr	a3,vlenb
   21d40:	0026d793          	srli	a5,a3,0x2
   21d44:	4541                	li	a0,16
   21d46:	85be                	mv	a1,a5
   21d48:	00f56363          	bltu	a0,a5,21d4e <_ZL13close_at_filev+0xf0>
   21d4c:	45c1                	li	a1,16
   21d4e:	238ab503          	ld	a0,568(s5)
   21d52:	003b1813          	slli	a6,s6,0x3
   21d56:	00bb6963          	bltu	s6,a1,21d68 <_ZL13close_at_filev+0x10a>
   21d5a:	00169713          	slli	a4,a3,0x1
   21d5e:	40aa05b3          	sub	a1,s4,a0
   21d62:	15e1                	addi	a1,a1,-8
   21d64:	08e5f463          	bgeu	a1,a4,21dec <_ZL13close_at_filev+0x18e>
   21d68:	4601                	li	a2,0
   21d6a:	060e                	slli	a2,a2,0x3
   21d6c:	00a80733          	add	a4,a6,a0
   21d70:	00a606b3          	add	a3,a2,a0
   21d74:	9652                	add	a2,a2,s4
   21d76:	06a1                	addi	a3,a3,8
   21d78:	0721                	addi	a4,a4,8
   21d7a:	628c                	ld	a1,0(a3)
   21d7c:	06a1                	addi	a3,a3,8
   21d7e:	e20c                	sd	a1,0(a2)
   21d80:	0621                	addi	a2,a2,8
   21d82:	fee69ce3          	bne	a3,a4,21d7a <_ZL13close_at_filev+0x11c>
   21d86:	9852                	add	a6,a6,s4
   21d88:	00083023          	sd	zero,0(a6)
_ZN3vecIPKc7va_heap8vl_embedE8truncateEj():
   21d8c:	00052223          	sw	zero,4(a0)
_ZL13close_at_filev():
   21d90:	c4c5                	beqz	s1,21e38 <_ZL13close_at_filev+0x1da>
   21d92:	8552                	mv	a0,s4
   21d94:	85a6                	mv	a1,s1
   21d96:	6597c0ef          	jal	9ebee <writeargv>
   21d9a:	e955                	bnez	a0,21e4e <_ZL13close_at_filev+0x1f0>
   21d9c:	8526                	mv	a0,s1
   21d9e:	8f2f20ef          	jal	13e90 <fclose@plt>
   21da2:	55fd                	li	a1,-1
   21da4:	0cb50063          	beq	a0,a1,21e64 <_ZL13close_at_filev+0x206>
_ZL9store_argPKcii():
   21da8:	029ac503          	lbu	a0,41(s5)
   21dac:	fb343423          	sd	s3,-88(s0)
   21db0:	e501                	bnez	a0,21db8 <_ZL13close_at_filev+0x15a>
   21db2:	0c8a8513          	addi	a0,s5,200
   21db6:	a019                	j	21dbc <_ZL13close_at_filev+0x15e>
   21db8:	238a8513          	addi	a0,s5,568
   21dbc:	fa840593          	addi	a1,s0,-88
   21dc0:	62e020ef          	jal	243ee <_ZN3vecIPKc7va_heap6vl_ptrE9safe_pushERKS1_>
_ZL13close_at_filev():
   21dc4:	05caa503          	lw	a0,92(s5)
   21dc8:	00153593          	seqz	a1,a0
   21dcc:	854a                	mv	a0,s2
   21dce:	862e                	mv	a2,a1
   21dd0:	de0f30ef          	jal	153b0 <_Z16record_temp_filePKcii>
   21dd4:	fa040113          	addi	sp,s0,-96
   21dd8:	60e6                	ld	ra,88(sp)
   21dda:	6446                	ld	s0,80(sp)
   21ddc:	64a6                	ld	s1,72(sp)
   21dde:	6906                	ld	s2,64(sp)
   21de0:	79e2                	ld	s3,56(sp)
   21de2:	7a42                	ld	s4,48(sp)
   21de4:	7aa2                	ld	s5,40(sp)
   21de6:	7b02                	ld	s6,32(sp)
   21de8:	6125                	addi	sp,sp,96
   21dea:	8082                	ret
   21dec:	40f005b3          	neg	a1,a5
   21df0:	0165f633          	and	a2,a1,s6
   21df4:	40f605b3          	sub	a1,a2,a5
   21df8:	02f5d5b3          	divu	a1,a1,a5
   21dfc:	00850793          	addi	a5,a0,8
   21e00:	828d                	srli	a3,a3,0x3
   21e02:	0592                	slli	a1,a1,0x4
   21e04:	05c1                	addi	a1,a1,16
   21e06:	02d585b3          	mul	a1,a1,a3
   21e0a:	95d2                	add	a1,a1,s4
   21e0c:	86d2                	mv	a3,s4
   21e0e:	2287f407          	vl2re64.v	v8,(a5)
   21e12:	22868427          	vs2r.v	v8,(a3)
   21e16:	96ba                	add	a3,a3,a4
   21e18:	97ba                	add	a5,a5,a4
   21e1a:	feb69ae3          	bne	a3,a1,21e0e <_ZL13close_at_filev+0x1b0>
   21e1e:	f76604e3          	beq	a2,s6,21d86 <_ZL13close_at_filev+0x128>
   21e22:	b7a1                	j	21d6a <_ZL13close_at_filev+0x10c>
   21e24:	001a8537          	lui	a0,0x1a8
   21e28:	9e053503          	ld	a0,-1568(a0) # 1a79e0 <input_location>
   21e2c:	000a65b7          	lui	a1,0xa6
   21e30:	06058593          	addi	a1,a1,96 # a6060 <_ZZL9init_specvE2tf+0xacc>
   21e34:	1222c0ef          	jal	4df56 <_Z11fatal_errormPKcz>
   21e38:	001a8537          	lui	a0,0x1a8
   21e3c:	9e053503          	ld	a0,-1568(a0) # 1a79e0 <input_location>
   21e40:	000a65b7          	lui	a1,0xa6
   21e44:	08758593          	addi	a1,a1,135 # a6087 <_ZZL9init_specvE2tf+0xaf3>
   21e48:	864a                	mv	a2,s2
   21e4a:	10c2c0ef          	jal	4df56 <_Z11fatal_errormPKcz>
   21e4e:	001a8537          	lui	a0,0x1a8
   21e52:	9e053503          	ld	a0,-1568(a0) # 1a79e0 <input_location>
   21e56:	000a65b7          	lui	a1,0xa6
   21e5a:	0b158593          	addi	a1,a1,177 # a60b1 <_ZZL9init_specvE2tf+0xb1d>
   21e5e:	864a                	mv	a2,s2
   21e60:	0f62c0ef          	jal	4df56 <_Z11fatal_errormPKcz>
   21e64:	001a8537          	lui	a0,0x1a8
   21e68:	9e053503          	ld	a0,-1568(a0) # 1a79e0 <input_location>
   21e6c:	000a65b7          	lui	a1,0xa6
   21e70:	0df58593          	addi	a1,a1,223 # a60df <_ZZL9init_specvE2tf+0xb4b>
   21e74:	864a                	mv	a2,s2
   21e76:	0e02c0ef          	jal	4df56 <_Z11fatal_errormPKcz>
"""


@lru_cache(maxsize=2)
def load_followup_program():
    """Parse the follow-up extract into a CFG-backed ``Program``."""

    from chimera.preprocess.offline.analysis.arch.riscv.rvv.services import (
        RvvServices,
    )
    from chimera.preprocess.offline.analysis.arch.riscv.services import (
        RiscvServices,
    )
    from chimera.preprocess.offline.analysis.program_model.parser import parse_dump
    from chimera.preprocess.offline.analysis.toolchain.objdump import LinuxObjdump

    adapter = LinuxObjdump("objdump")
    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory) / "xgcc-followup.dump"
        source.write_text(FOLLOWUP_FUNCTIONS_DUMP, encoding="utf-8")
        parsed = parse_dump(
            source,
            adapter.parse_format,
            is_external_trampoline=adapter.is_external_trampoline,
            retain_dump_lines=False,
        )
    return RiscvServices(RvvServices()).build_cfg(parsed)


# endregion
# region Recursive-call evidence (CFG call-edge fix, 2026-09-21)

#: The same ELF as the gate-2 extract (``build-gate2/gcc/xgcc``, sha256
#: 3b022cb2…), dumped again for the three recursive functions whose fixed
#: stack frames the call-edge bug turned into false VLEN frames.  ``elf_add``
#: and ``dwarf_lookup_pc`` are libbacktrace functions linked into xgcc,
#: ``d_count_templates_scopes`` is libiberty.  Instruction addresses, machine
#: code and function boundaries are verbatim; only the dump header with the
#: absolute build path was removed, so this fixture depends on neither the
#: build directory nor the desktop evidence archive.
RECURSIVE_FUNCTIONS = (
    "elf_add",
    "dwarf_lookup_pc",
    "d_count_templates_scopes",
)

ELF_ADD = "elf_add"
#: The fixed 1888-byte frame: prologue allocation and epilogue restore.
#: Neither may produce a VLEN stack-frame marker or a warning.
ELF_ADD_ALLOCATION = 0x88E82
ELF_ADD_RESTORE = 0x893E6
#: The three self-recursive calls; their targets must stay resolvable.
ELF_ADD_RECURSIVE_CALLS = (0x89946, 0x899BE, 0x89B66)
#: The unresolved indirect calls that used to be reported as findings while
#: the false frame state was live at them.
ELF_ADD_INDIRECT_CALLS = (0x88EEE, 0x89098, 0x89CC8)

DWARF_LOOKUP_PC = "dwarf_lookup_pc"
DWARF_LOOKUP_PC_ALLOCATION = 0x8E8FE
DWARF_LOOKUP_PC_RESTORE = 0x8EAE2
DWARF_LOOKUP_PC_RECURSIVE_CALL = 0x8EC82
DWARF_LOOKUP_PC_INDIRECT_CALLS = (0x8EC94, 0x8ED5E)
#: Vector stores through pointers: real vector work that must survive the fix.
DWARF_LOOKUP_PC_VECTOR_STORES = (0x8EA6E, 0x8EA74)

D_COUNT_TEMPLATES_SCOPES = "d_count_templates_scopes"
D_COUNT_TEMPLATES_SCOPES_ALLOCATION = 0x996FE
D_COUNT_TEMPLATES_SCOPES_RESTORE = 0x99794
D_COUNT_TEMPLATES_SCOPES_RECURSIVE_CALLS = (0x99778, 0x99780)
#: The jump-table dispatch (``jr a2`` after loading the target from a table):
#: it stays unresolved and therefore conservative.
D_COUNT_TEMPLATES_SCOPES_JUMP_TABLE = 0x99742

RECURSIVE_FUNCTIONS_DUMP = r"""\
0000000000088e82 <elf_add>:
   88e82:	8a010113          	addi	sp,sp,-1888
   88e86:	74113c23          	sd	ra,1880(sp)
   88e8a:	74813823          	sd	s0,1872(sp)
   88e8e:	74913423          	sd	s1,1864(sp)
   88e92:	75213023          	sd	s2,1856(sp)
   88e96:	73313c23          	sd	s3,1848(sp)
   88e9a:	73413823          	sd	s4,1840(sp)
   88e9e:	73513423          	sd	s5,1832(sp)
   88ea2:	73613023          	sd	s6,1824(sp)
   88ea6:	71713c23          	sd	s7,1816(sp)
   88eaa:	71813823          	sd	s8,1808(sp)
   88eae:	71913423          	sd	s9,1800(sp)
   88eb2:	71a13023          	sd	s10,1792(sp)
   88eb6:	6fb13c23          	sd	s11,1784(sp)
   88eba:	8b72                	mv	s6,t3
   88ebc:	8bc6                	mv	s7,a7
   88ebe:	8932                	mv	s2,a2
   88ec0:	77013603          	ld	a2,1904(sp)
   88ec4:	8caa                	mv	s9,a0
   88ec6:	e609                	bnez	a2,88ed0 <elf_add+0x4e>
   88ec8:	000f2023          	sw	zero,0(t5)
   88ecc:	000fa023          	sw	zero,0(t6)
   88ed0:	22013c23          	sd	zero,568(sp)
   88ed4:	24010023          	sb	zero,576(sp)
   88ed8:	ce89                	beqz	a3,88ef2 <elf_add+0x70>
   88eda:	03f00513          	li	a0,63
   88ede:	06e56663          	bltu	a0,a4,88f4a <elf_add+0xc8>
   88ee2:	00061517          	auipc	a0,0x61
   88ee6:	7e250593          	addi	a1,a0,2018 # ea6c4 <_ZZL13pch_open_fileP10cpp_readerP9_cpp_filePbE9extension+0x22a9>
   88eea:	855a                	mv	a0,s6
   88eec:	4601                	li	a2,0
   88eee:	9b82                	jalr	s7
   88ef0:	ae7d                	j	892ae <elf_add+0x42c>
   88ef2:	fe32                	sd	a2,312(sp)
   88ef4:	8dae                	mv	s11,a1
   88ef6:	8d42                	mv	s10,a6
   88ef8:	8c7a                	mv	s8,t5
   88efa:	8ab6                	mv	s5,a3
   88efc:	8a3a                	mv	s4,a4
   88efe:	89be                	mv	s3,a5
   88f00:	8476                	mv	s0,t4
   88f02:	84fe                	mv	s1,t6
   88f04:	4505                	li	a0,1
   88f06:	6ea12823          	sw	a0,1776(sp)
   88f0a:	04000693          	li	a3,64
   88f0e:	6d810813          	addi	a6,sp,1752
   88f12:	8566                	mv	a0,s9
   88f14:	85ca                	mv	a1,s2
   88f16:	4601                	li	a2,0
   88f18:	875e                	mv	a4,s7
   88f1a:	87da                	mv	a5,s6
   88f1c:	304030ef          	jal	8c220 <backtrace_get_view>
   88f20:	38050763          	beqz	a0,892ae <elf_add+0x42c>
   88f24:	f9ee                	sd	s11,240(sp)
   88f26:	ee6a                	sd	s10,280(sp)
   88f28:	e262                	sd	s8,256(sp)
   88f2a:	f656                	sd	s5,296(sp)
   88f2c:	fa52                	sd	s4,304(sp)
   88f2e:	ea4e                	sd	s3,272(sp)
   88f30:	e622                	sd	s0,264(sp)
   88f32:	fda6                	sd	s1,248(sp)
   88f34:	eae6                	sd	s9,336(sp)
   88f36:	e2ca                	sd	s2,320(sp)
   88f38:	eede                	sd	s7,344(sp)
   88f3a:	e6da                	sd	s6,328(sp)
   88f3c:	6f012503          	lw	a0,1776(sp)
   88f40:	6d813583          	ld	a1,1752(sp)
   88f44:	00153513          	seqz	a0,a0
   88f48:	a815                	j	88f7c <elf_add+0xfa>
   88f4a:	fe32                	sd	a2,312(sp)
   88f4c:	f9ae                	sd	a1,240(sp)
   88f4e:	ee42                	sd	a6,280(sp)
   88f50:	e27a                	sd	t5,256(sp)
   88f52:	fa3a                	sd	a4,304(sp)
   88f54:	ea3e                	sd	a5,272(sp)
   88f56:	e676                	sd	t4,264(sp)
   88f58:	fdfe                	sd	t6,248(sp)
   88f5a:	eae6                	sd	s9,336(sp)
   88f5c:	e2ca                	sd	s2,320(sp)
   88f5e:	eede                	sd	s7,344(sp)
   88f60:	e6da                	sd	s6,328(sp)
   88f62:	04000513          	li	a0,64
   88f66:	6cd13c23          	sd	a3,1752(sp)
   88f6a:	6e013023          	sd	zero,1760(sp)
   88f6e:	6ea13423          	sd	a0,1768(sp)
   88f72:	6e012823          	sw	zero,1776(sp)
   88f76:	4505                	li	a0,1
   88f78:	f636                	sd	a3,296(sp)
   88f7a:	85b6                	mv	a1,a3
   88f7c:	0005c703          	lbu	a4,0(a1)
   88f80:	0015c783          	lbu	a5,1(a1)
   88f84:	0025cf03          	lbu	t5,2(a1)
   88f88:	0035c383          	lbu	t2,3(a1)
   88f8c:	0045c803          	lbu	a6,4(a1)
   88f90:	0055c683          	lbu	a3,5(a1)
   88f94:	0065cd03          	lbu	s10,6(a1)
   88f98:	0105c903          	lbu	s2,16(a1)
   88f9c:	0115cc83          	lbu	s9,17(a1)
   88fa0:	0125c603          	lbu	a2,18(a1)
   88fa4:	f5b2                	sd	a2,232(sp)
   88fa6:	0135c603          	lbu	a2,19(a1)
   88faa:	f1b2                	sd	a2,224(sp)
   88fac:	0285c483          	lbu	s1,40(a1)
   88fb0:	0295cc03          	lbu	s8,41(a1)
   88fb4:	02a5ca03          	lbu	s4,42(a1)
   88fb8:	02b5cd83          	lbu	s11,43(a1)
   88fbc:	02c5cb83          	lbu	s7,44(a1)
   88fc0:	02d5cb03          	lbu	s6,45(a1)
   88fc4:	02e5c883          	lbu	a7,46(a1)
   88fc8:	02f5c303          	lbu	t1,47(a1)
   88fcc:	0305c603          	lbu	a2,48(a1)
   88fd0:	edb2                	sd	a2,216(sp)
   88fd2:	0315c603          	lbu	a2,49(a1)
   88fd6:	e9b2                	sd	a2,208(sp)
   88fd8:	0325c603          	lbu	a2,50(a1)
   88fdc:	e5b2                	sd	a2,200(sp)
   88fde:	0335c603          	lbu	a2,51(a1)
   88fe2:	e1b2                	sd	a2,192(sp)
   88fe4:	03c5ca83          	lbu	s5,60(a1)
   88fe8:	03d5c403          	lbu	s0,61(a1)
   88fec:	03e5ce83          	lbu	t4,62(a1)
   88ff0:	03f5c983          	lbu	s3,63(a1)
   88ff4:	e121                	bnez	a0,89034 <elf_add+0x1b2>
   88ff6:	6d810593          	addi	a1,sp,1752
   88ffa:	6556                	ld	a0,336(sp)
   88ffc:	6676                	ld	a2,344(sp)
   88ffe:	fd66                	sd	s9,184(sp)
   89000:	f236                	sd	a3,288(sp)
   89002:	66b6                	ld	a3,328(sp)
   89004:	f94e                	sd	s3,176(sp)
   89006:	e976                	sd	t4,144(sp)
   89008:	e122                	sd	s0,128(sp)
   8900a:	f146                	sd	a7,160(sp)
   8900c:	8c9a                	mv	s9,t1
   8900e:	f542                	sd	a6,168(sp)
   89010:	ed3a                	sd	a4,152(sp)
   89012:	89be                	mv	s3,a5
   89014:	e51e                	sd	t2,136(sp)
   89016:	847a                	mv	s0,t5
   89018:	296030ef          	jal	8c2ae <backtrace_release_view>
   8901c:	8f22                	mv	t5,s0
   8901e:	63aa                	ld	t2,136(sp)
   89020:	87ce                	mv	a5,s3
   89022:	676a                	ld	a4,152(sp)
   89024:	782a                	ld	a6,168(sp)
   89026:	8366                	mv	t1,s9
   89028:	788a                	ld	a7,160(sp)
   8902a:	640a                	ld	s0,128(sp)
   8902c:	6eca                	ld	t4,144(sp)
   8902e:	79ca                	ld	s3,176(sp)
   89030:	7692                	ld	a3,288(sp)
   89032:	7cea                	ld	s9,184(sp)
   89034:	07f00513          	li	a0,127
   89038:	02a71e63          	bne	a4,a0,89074 <elf_add+0x1f2>
   8903c:	04500513          	li	a0,69
   89040:	02a79a63          	bne	a5,a0,89074 <elf_add+0x1f2>
   89044:	04c00513          	li	a0,76
   89048:	02af1663          	bne	t5,a0,89074 <elf_add+0x1f2>
   8904c:	04600513          	li	a0,70
   89050:	02a39263          	bne	t2,a0,89074 <elf_add+0x1f2>
   89054:	4505                	li	a0,1
   89056:	02ad1463          	bne	s10,a0,8907e <elf_add+0x1fc>
   8905a:	4509                	li	a0,2
   8905c:	02a81663          	bne	a6,a0,89088 <elf_add+0x206>
   89060:	ffd68513          	addi	a0,a3,-3
   89064:	55f5                	li	a1,-3
   89066:	02a5ef63          	bltu	a1,a0,890a4 <elf_add+0x222>
   8906a:	00061517          	auipc	a0,0x61
   8906e:	59f50593          	addi	a1,a0,1439 # ea609 <_ZZL13pch_open_fileP10cpp_readerP9_cpp_filePbE9extension+0x21ee>
   89072:	a839                	j	89090 <elf_add+0x20e>
   89074:	00061517          	auipc	a0,0x61
   89078:	52650593          	addi	a1,a0,1318 # ea59a <_ZZL13pch_open_fileP10cpp_readerP9_cpp_filePbE9extension+0x217f>
   8907c:	a811                	j	89090 <elf_add+0x20e>
   8907e:	00061517          	auipc	a0,0x61
   89082:	53750593          	addi	a1,a0,1335 # ea5b5 <_ZZL13pch_open_fileP10cpp_readerP9_cpp_filePbE9extension+0x219a>
   89086:	a029                	j	89090 <elf_add+0x20e>
   89088:	00061517          	auipc	a0,0x61
   8908c:	55950593          	addi	a1,a0,1369 # ea5e1 <_ZZL13pch_open_fileP10cpp_readerP9_cpp_filePbE9extension+0x21c6>
   89090:	6b36                	ld	s6,328(sp)
   89092:	855a                	mv	a0,s6
   89094:	4601                	li	a2,0
   89096:	6bf6                	ld	s7,344(sp)
   89098:	9b82                	jalr	s7
   8909a:	4981                	li	s3,0
   8909c:	4d81                	li	s11,0
   8909e:	6916                	ld	s2,320(sp)
   890a0:	6cd6                	ld	s9,336(sp)
   890a2:	ac01                	j	892b2 <elf_add+0x430>
   890a4:	76813583          	ld	a1,1896(sp)
   890a8:	557d                	li	a0,-1
   890aa:	c599                	beqz	a1,890b8 <elf_add+0x236>
   890ac:	0ca2                	slli	s9,s9,0x8
   890ae:	012ce5b3          	or	a1,s9,s2
   890b2:	460d                	li	a2,3
   890b4:	2ec58f63          	beq	a1,a2,893b2 <elf_add+0x530>
   890b8:	f236                	sd	a3,288(sp)
   890ba:	008b1613          	slli	a2,s6,0x8
   890be:	08c2                	slli	a7,a7,0x10
   890c0:	0362                	slli	t1,t1,0x18
   890c2:	008c1513          	slli	a0,s8,0x8
   890c6:	010a1293          	slli	t0,s4,0x10
   890ca:	018d9593          	slli	a1,s11,0x18
   890ce:	00841693          	slli	a3,s0,0x8
   890d2:	09a2                	slli	s3,s3,0x8
   890d4:	017663b3          	or	t2,a2,s7
   890d8:	6841                	lui	a6,0x10
   890da:	01136633          	or	a2,t1,a7
   890de:	8d45                	or	a0,a0,s1
   890e0:	0055e5b3          	or	a1,a1,t0
   890e4:	0156ed33          	or	s10,a3,s5
   890e8:	01d9ea33          	or	s4,s3,t4
   890ec:	fff80793          	addi	a5,a6,-1 # ffff <_PROCEDURE_LINKAGE_TABLE_-0x3d51>
   890f0:	00766733          	or	a4,a2,t2
   890f4:	8d4d                	or	a0,a0,a1
   890f6:	00fa75b3          	and	a1,s4,a5
   890fa:	001d3613          	seqz	a2,s10
   890fe:	1702                	slli	a4,a4,0x20
   89100:	8dbd                	xor	a1,a1,a5
   89102:	0015b593          	seqz	a1,a1
   89106:	8dd1                	or	a1,a1,a2
   89108:	00a764b3          	or	s1,a4,a0
   8910c:	6cd6                	ld	s9,336(sp)
   8910e:	c9ad                	beqz	a1,89180 <elf_add+0x2fe>
   89110:	6b36                	ld	s6,328(sp)
   89112:	6bf6                	ld	s7,344(sp)
   89114:	c8a5                	beqz	s1,89184 <elf_add+0x302>
   89116:	47a1                	li	a5,8
   89118:	24810e13          	addi	t3,sp,584
   8911c:	8566                	mv	a0,s9
   8911e:	6916                	ld	s2,320(sp)
   89120:	85ca                	mv	a1,s2
   89122:	7632                	ld	a2,296(sp)
   89124:	76d2                	ld	a3,304(sp)
   89126:	8726                	mv	a4,s1
   89128:	885e                	mv	a6,s7
   8912a:	88da                	mv	a7,s6
   8912c:	043020ef          	jal	8b96e <elf_get_view>
   89130:	16050f63          	beqz	a0,892ae <elf_add+0x42c>
   89134:	24813503          	ld	a0,584(sp)
   89138:	000d1463          	bnez	s10,89140 <elf_add+0x2be>
   8913c:	02053d03          	ld	s10,32(a0)
   89140:	65c1                	lui	a1,0x10
   89142:	15fd                	addi	a1,a1,-1 # ffff <_PROCEDURE_LINKAGE_TABLE_-0x3d51>
   89144:	02ba1463          	bne	s4,a1,8916c <elf_add+0x2ea>
   89148:	5508                	lw	a0,40(a0)
   8914a:	000d059b          	sext.w	a1,s10
   8914e:	00b535b3          	sltu	a1,a0,a1
   89152:	0105561b          	srliw	a2,a0,0x10
   89156:	fff5c593          	not	a1,a1
   8915a:	00c03633          	snez	a2,a2
   8915e:	8df1                	and	a1,a1,a2
   89160:	40b005bb          	negw	a1,a1
   89164:	f005f593          	andi	a1,a1,-256
   89168:	00b50a33          	add	s4,a0,a1
   8916c:	26012503          	lw	a0,608(sp)
   89170:	c919                	beqz	a0,89186 <elf_add+0x304>
   89172:	04ac                	addi	a1,sp,584
   89174:	8566                	mv	a0,s9
   89176:	865e                	mv	a2,s7
   89178:	86da                	mv	a3,s6
   8917a:	134030ef          	jal	8c2ae <backtrace_release_view>
   8917e:	a021                	j	89186 <elf_add+0x304>
   89180:	6b36                	ld	s6,328(sp)
   89182:	6bf6                	ld	s7,344(sp)
   89184:	6916                	ld	s2,320(sp)
   89186:	000d041b          	sext.w	s0,s10
   8918a:	4981                	li	s3,0
   8918c:	10040563          	beqz	s0,89296 <elf_add+0x414>
   89190:	000a051b          	sext.w	a0,s4
   89194:	10050163          	beqz	a0,89296 <elf_add+0x414>
   89198:	04048713          	addi	a4,s1,64
   8919c:	fffd0513          	addi	a0,s10,-1
   891a0:	1502                	slli	a0,a0,0x20
   891a2:	01a55793          	srli	a5,a0,0x1a
   891a6:	6b810e13          	addi	t3,sp,1720
   891aa:	8566                	mv	a0,s9
   891ac:	85ca                	mv	a1,s2
   891ae:	7632                	ld	a2,296(sp)
   891b0:	76d2                	ld	a3,304(sp)
   891b2:	885e                	mv	a6,s7
   891b4:	88da                	mv	a7,s6
   891b6:	7b8020ef          	jal	8b96e <elf_get_view>
   891ba:	0e050a63          	beqz	a0,892ae <elf_add+0x42c>
   891be:	6b813483          	ld	s1,1720(sp)
   891c2:	fffa0513          	addi	a0,s4,-1
   891c6:	1502                	slli	a0,a0,0x20
   891c8:	8169                	srli	a0,a0,0x1a
   891ca:	9526                	add	a0,a0,s1
   891cc:	6d18                	ld	a4,24(a0)
   891ce:	711c                	ld	a5,32(a0)
   891d0:	69810e13          	addi	t3,sp,1688
   891d4:	8566                	mv	a0,s9
   891d6:	85ca                	mv	a1,s2
   891d8:	7632                	ld	a2,296(sp)
   891da:	76d2                	ld	a3,304(sp)
   891dc:	f53e                	sd	a5,168(sp)
   891de:	885e                	mv	a6,s7
   891e0:	88da                	mv	a7,s6
   891e2:	78c020ef          	jal	8b96e <elf_get_view>
   891e6:	c955                	beqz	a0,8929a <elf_add+0x418>
   891e8:	69813503          	ld	a0,1688(sp)
   891ec:	f12a                	sd	a0,160(sp)
   891ee:	57810513          	addi	a0,sp,1400
   891f2:	12000613          	li	a2,288
   891f6:	4581                	li	a1,0
   891f8:	b188b0ef          	jal	14510 <memset@plt>
   891fc:	45810513          	addi	a0,sp,1112
   89200:	12000613          	li	a2,288
   89204:	4581                	li	a1,0
   89206:	b0a8b0ef          	jal	14510 <memset@plt>
   8920a:	4509                	li	a0,2
   8920c:	1ea46063          	bltu	s0,a0,893ec <elf_add+0x56a>
   89210:	f822                	sd	s0,48(sp)
   89212:	e502                	sd	zero,136(sp)
   89214:	ed02                	sd	zero,152(sp)
   89216:	f902                	sd	zero,176(sp)
   89218:	e482                	sd	zero,72(sp)
   8921a:	e902                	sd	zero,144(sp)
   8921c:	4a81                	li	s5,0
   8921e:	f482                	sd	zero,104(sp)
   89220:	f082                	sd	zero,96(sp)
   89222:	4981                	li	s3,0
   89224:	e102                	sd	zero,128(sp)
   89226:	fc82                	sd	zero,120(sp)
   89228:	8726                	mv	a4,s1
   8922a:	4a01                	li	s4,0
   8922c:	e882                	sd	zero,80(sp)
   8922e:	ec82                	sd	zero,88(sp)
   89230:	f882                	sd	zero,112(sp)
   89232:	fd02                	sd	zero,184(sp)
   89234:	644e                	ld	s0,208(sp)
   89236:	0422                	slli	s0,s0,0x8
   89238:	65ae                	ld	a1,200(sp)
   8923a:	05c2                	slli	a1,a1,0x10
   8923c:	660e                	ld	a2,192(sp)
   8923e:	0662                	slli	a2,a2,0x18
   89240:	768e                	ld	a3,224(sp)
   89242:	06a2                	slli	a3,a3,0x8
   89244:	78013783          	ld	a5,1920(sp)
   89248:	77813483          	ld	s1,1912(sp)
   8924c:	656e                	ld	a0,216(sp)
   8924e:	8d41                	or	a0,a0,s0
   89250:	8dd1                	or	a1,a1,a2
   89252:	762e                	ld	a2,232(sp)
   89254:	8e55                	or	a2,a2,a3
   89256:	8d4d                	or	a0,a0,a1
   89258:	75f2                	ld	a1,312(sp)
   8925a:	00b035b3          	snez	a1,a1
   8925e:	020d1693          	slli	a3,s10,0x20
   89262:	9281                	srli	a3,a3,0x20
   89264:	01564613          	xori	a2,a2,21
   89268:	fff68d93          	addi	s11,a3,-1
   8926c:	8909                	andi	a0,a0,2
   8926e:	8d51                	or	a0,a0,a2
   89270:	e1a6                	sd	s1,192(sp)
   89272:	0014b613          	seqz	a2,s1
   89276:	8df1                	and	a1,a1,a2
   89278:	f1ae                	sd	a1,224(sp)
   8927a:	e5be                	sd	a5,200(sp)
   8927c:	02079593          	slli	a1,a5,0x20
   89280:	00153513          	seqz	a0,a0
   89284:	edaa                	sd	a0,216(sp)
   89286:	9181                	srli	a1,a1,0x20
   89288:	e0ae                	sd	a1,64(sp)
   8928a:	fc3a                	sd	a4,56(sp)
   8928c:	02070413          	addi	s0,a4,32
   89290:	4505                	li	a0,1
   89292:	f5aa                	sd	a0,232(sp)
   89294:	ac35                	j	894d0 <elf_add+0x64e>
   89296:	8dce                	mv	s11,s3
   89298:	a829                	j	892b2 <elf_add+0x430>
   8929a:	6d012503          	lw	a0,1744(sp)
   8929e:	c901                	beqz	a0,892ae <elf_add+0x42c>
   892a0:	6b810593          	addi	a1,sp,1720
   892a4:	8566                	mv	a0,s9
   892a6:	865e                	mv	a2,s7
   892a8:	86da                	mv	a3,s6
   892aa:	004030ef          	jal	8c2ae <backtrace_release_view>
   892ae:	4981                	li	s3,0
   892b0:	4d81                	li	s11,0
   892b2:	23814503          	lbu	a0,568(sp)
   892b6:	c911                	beqz	a0,892ca <elf_add+0x448>
   892b8:	26012503          	lw	a0,608(sp)
   892bc:	c519                	beqz	a0,892ca <elf_add+0x448>
   892be:	04ac                	addi	a1,sp,584
   892c0:	8566                	mv	a0,s9
   892c2:	865e                	mv	a2,s7
   892c4:	86da                	mv	a3,s6
   892c6:	7e9020ef          	jal	8c2ae <backtrace_release_view>
   892ca:	23914503          	lbu	a0,569(sp)
   892ce:	c911                	beqz	a0,892e2 <elf_add+0x460>
   892d0:	28012503          	lw	a0,640(sp)
   892d4:	c519                	beqz	a0,892e2 <elf_add+0x460>
   892d6:	14ac                	addi	a1,sp,616
   892d8:	8566                	mv	a0,s9
   892da:	865e                	mv	a2,s7
   892dc:	86da                	mv	a3,s6
   892de:	7d1020ef          	jal	8c2ae <backtrace_release_view>
   892e2:	23a14503          	lbu	a0,570(sp)
   892e6:	c911                	beqz	a0,892fa <elf_add+0x478>
   892e8:	2a012503          	lw	a0,672(sp)
   892ec:	c519                	beqz	a0,892fa <elf_add+0x478>
   892ee:	052c                	addi	a1,sp,648
   892f0:	8566                	mv	a0,s9
   892f2:	865e                	mv	a2,s7
   892f4:	86da                	mv	a3,s6
   892f6:	7b9020ef          	jal	8c2ae <backtrace_release_view>
   892fa:	23b14503          	lbu	a0,571(sp)
   892fe:	c911                	beqz	a0,89312 <elf_add+0x490>
   89300:	2c012503          	lw	a0,704(sp)
   89304:	c519                	beqz	a0,89312 <elf_add+0x490>
   89306:	152c                	addi	a1,sp,680
   89308:	8566                	mv	a0,s9
   8930a:	865e                	mv	a2,s7
   8930c:	86da                	mv	a3,s6
   8930e:	7a1020ef          	jal	8c2ae <backtrace_release_view>
   89312:	23c14503          	lbu	a0,572(sp)
   89316:	c911                	beqz	a0,8932a <elf_add+0x4a8>
   89318:	2e012503          	lw	a0,736(sp)
   8931c:	c519                	beqz	a0,8932a <elf_add+0x4a8>
   8931e:	05ac                	addi	a1,sp,712
   89320:	8566                	mv	a0,s9
   89322:	865e                	mv	a2,s7
   89324:	86da                	mv	a3,s6
   89326:	789020ef          	jal	8c2ae <backtrace_release_view>
   8932a:	23d14503          	lbu	a0,573(sp)
   8932e:	c911                	beqz	a0,89342 <elf_add+0x4c0>
   89330:	30012503          	lw	a0,768(sp)
   89334:	c519                	beqz	a0,89342 <elf_add+0x4c0>
   89336:	15ac                	addi	a1,sp,744
   89338:	8566                	mv	a0,s9
   8933a:	865e                	mv	a2,s7
   8933c:	86da                	mv	a3,s6
   8933e:	771020ef          	jal	8c2ae <backtrace_release_view>
   89342:	23e14503          	lbu	a0,574(sp)
   89346:	c911                	beqz	a0,8935a <elf_add+0x4d8>
   89348:	32012503          	lw	a0,800(sp)
   8934c:	c519                	beqz	a0,8935a <elf_add+0x4d8>
   8934e:	062c                	addi	a1,sp,776
   89350:	8566                	mv	a0,s9
   89352:	865e                	mv	a2,s7
   89354:	86da                	mv	a3,s6
   89356:	759020ef          	jal	8c2ae <backtrace_release_view>
   8935a:	23f14503          	lbu	a0,575(sp)
   8935e:	c911                	beqz	a0,89372 <elf_add+0x4f0>
   89360:	34012503          	lw	a0,832(sp)
   89364:	c519                	beqz	a0,89372 <elf_add+0x4f0>
   89366:	162c                	addi	a1,sp,808
   89368:	8566                	mv	a0,s9
   8936a:	865e                	mv	a2,s7
   8936c:	86da                	mv	a3,s6
   8936e:	741020ef          	jal	8c2ae <backtrace_release_view>
   89372:	24014503          	lbu	a0,576(sp)
   89376:	c911                	beqz	a0,8938a <elf_add+0x508>
   89378:	36012503          	lw	a0,864(sp)
   8937c:	c519                	beqz	a0,8938a <elf_add+0x508>
   8937e:	06ac                	addi	a1,sp,840
   89380:	8566                	mv	a0,s9
   89382:	865e                	mv	a2,s7
   89384:	86da                	mv	a3,s6
   89386:	729020ef          	jal	8c2ae <backtrace_release_view>
   8938a:	00098c63          	beqz	s3,893a2 <elf_add+0x520>
   8938e:	030da503          	lw	a0,48(s11)
   89392:	c901                	beqz	a0,893a2 <elf_add+0x520>
   89394:	018d8593          	addi	a1,s11,24
   89398:	8566                	mv	a0,s9
   8939a:	865e                	mv	a2,s7
   8939c:	86da                	mv	a3,s6
   8939e:	711020ef          	jal	8c2ae <backtrace_release_view>
   893a2:	00094763          	bltz	s2,893b0 <elf_add+0x52e>
   893a6:	854a                	mv	a0,s2
   893a8:	85de                	mv	a1,s7
   893aa:	865a                	mv	a2,s6
   893ac:	ecafc0ef          	jal	85a76 <backtrace_close>
   893b0:	4501                	li	a0,0
   893b2:	75813083          	ld	ra,1880(sp)
   893b6:	75013403          	ld	s0,1872(sp)
   893ba:	74813483          	ld	s1,1864(sp)
   893be:	74013903          	ld	s2,1856(sp)
   893c2:	73813983          	ld	s3,1848(sp)
   893c6:	73013a03          	ld	s4,1840(sp)
   893ca:	72813a83          	ld	s5,1832(sp)
   893ce:	72013b03          	ld	s6,1824(sp)
   893d2:	71813b83          	ld	s7,1816(sp)
   893d6:	71013c03          	ld	s8,1808(sp)
   893da:	70813c83          	ld	s9,1800(sp)
   893de:	70013d03          	ld	s10,1792(sp)
   893e2:	6f813d83          	ld	s11,1784(sp)
   893e6:	76010113          	addi	sp,sp,1888
   893ea:	8082                	ret
   893ec:	fd02                	sd	zero,184(sp)
   893ee:	f882                	sd	zero,112(sp)
   893f0:	ec82                	sd	zero,88(sp)
   893f2:	e882                	sd	zero,80(sp)
   893f4:	4a01                	li	s4,0
   893f6:	fc82                	sd	zero,120(sp)
   893f8:	e102                	sd	zero,128(sp)
   893fa:	4981                	li	s3,0
   893fc:	f082                	sd	zero,96(sp)
   893fe:	f482                	sd	zero,104(sp)
   89400:	fe02                	sd	zero,312(sp)
   89402:	e902                	sd	zero,144(sp)
   89404:	4a81                	li	s5,0
   89406:	f902                	sd	zero,176(sp)
   89408:	4d05                	li	s10,1
   8940a:	6df2                	ld	s11,280(sp)
   8940c:	6d012503          	lw	a0,1744(sp)
   89410:	c901                	beqz	a0,89420 <elf_add+0x59e>
   89412:	6b810593          	addi	a1,sp,1720
   89416:	8566                	mv	a0,s9
   89418:	865e                	mv	a2,s7
   8941a:	86da                	mv	a3,s6
   8941c:	693020ef          	jal	8c2ae <backtrace_release_view>
   89420:	6b012503          	lw	a0,1712(sp)
   89424:	c901                	beqz	a0,89434 <elf_add+0x5b2>
   89426:	69810593          	addi	a1,sp,1688
   8942a:	8566                	mv	a0,s9
   8942c:	865e                	mv	a2,s7
   8942e:	86da                	mv	a3,s6
   89430:	67f020ef          	jal	8c2ae <backtrace_release_view>
   89434:	480a8563          	beqz	s5,898be <elf_add+0xa3c>
   89438:	664a                	ld	a2,144(sp)
   8943a:	1602                	slli	a2,a2,0x20
   8943c:	9201                	srli	a2,a2,0x20
   8943e:	8566                	mv	a0,s9
   89440:	85d6                	mv	a1,s5
   89442:	86de                	mv	a3,s7
   89444:	875a                	mv	a4,s6
   89446:	6ea020ef          	jal	8bb30 <elf_open_debugfile_by_buildid>
   8944a:	46054a63          	bltz	a0,898be <elf_add+0xa3c>
   8944e:	842a                	mv	s0,a0
   89450:	41012503          	lw	a0,1040(sp)
   89454:	c519                	beqz	a0,89462 <elf_add+0x5e0>
   89456:	1fac                	addi	a1,sp,1016
   89458:	8566                	mv	a0,s9
   8945a:	865e                	mv	a2,s7
   8945c:	86da                	mv	a3,s6
   8945e:	651020ef          	jal	8c2ae <backtrace_release_view>
   89462:	79ee                	ld	s3,248(sp)
   89464:	6ab2                	ld	s5,264(sp)
   89466:	64d2                	ld	s1,272(sp)
   89468:	6a12                	ld	s4,256(sp)
   8946a:	7572                	ld	a0,312(sp)
   8946c:	c911                	beqz	a0,89480 <elf_add+0x5fe>
   8946e:	3f012503          	lw	a0,1008(sp)
   89472:	c519                	beqz	a0,89480 <elf_add+0x5fe>
   89474:	0fac                	addi	a1,sp,984
   89476:	8566                	mv	a0,s9
   89478:	865e                	mv	a2,s7
   8947a:	86da                	mv	a3,s6
   8947c:	633020ef          	jal	8c2ae <backtrace_release_view>
   89480:	756a                	ld	a0,184(sp)
   89482:	c911                	beqz	a0,89496 <elf_add+0x614>
   89484:	3d012503          	lw	a0,976(sp)
   89488:	c519                	beqz	a0,89496 <elf_add+0x614>
   8948a:	1f2c                	addi	a1,sp,952
   8948c:	8566                	mv	a0,s9
   8948e:	865e                	mv	a2,s7
   89490:	86da                	mv	a3,s6
   89492:	61d020ef          	jal	8c2ae <backtrace_release_view>
   89496:	f002                	sd	zero,32(sp)
   89498:	4505                	li	a0,1
   8949a:	0005c597          	auipc	a1,0x5c
   8949e:	ac458593          	addi	a1,a1,-1340 # e4f5e <_ZZ13trim_filenamePKcE9this_file+0x1a44>
   894a2:	a159                	j	89928 <elf_add+0xaa6>
   894a4:	ff043503          	ld	a0,-16(s0)
   894a8:	21813583          	ld	a1,536(sp)
   894ac:	20a13023          	sd	a0,512(sp)
   894b0:	20b13423          	sd	a1,520(sp)
   894b4:	6008                	ld	a0,0(s0)
   894b6:	4985                	li	s3,1
   894b8:	20a13823          	sd	a0,528(sp)
   894bc:	0408                	addi	a0,sp,512
   894be:	e12a                	sd	a0,128(sp)
   894c0:	04040413          	addi	s0,s0,64
   894c4:	1dfd                	addi	s11,s11,-1
   894c6:	752e                	ld	a0,232(sp)
   894c8:	2505                	addiw	a0,a0,1
   894ca:	f5aa                	sd	a0,232(sp)
   894cc:	520d8763          	beqz	s11,899fa <elf_add+0xb78>
   894d0:	fe442503          	lw	a0,-28(s0)
   894d4:	45ad                	li	a1,11
   894d6:	00b50863          	beq	a0,a1,894e6 <elf_add+0x664>
   894da:	4589                	li	a1,2
   894dc:	00b51763          	bne	a0,a1,894ea <elf_add+0x668>
   894e0:	752e                	ld	a0,232(sp)
   894e2:	e52a                	sd	a0,136(sp)
   894e4:	a019                	j	894ea <elf_add+0x668>
   894e6:	752e                	ld	a0,232(sp)
   894e8:	ed2a                	sd	a0,152(sp)
   894ea:	fe046503          	lwu	a0,-32(s0)
   894ee:	75aa                	ld	a1,168(sp)
   894f0:	4eb57c63          	bgeu	a0,a1,899e8 <elf_add+0xb66>
   894f4:	758a                	ld	a1,160(sp)
   894f6:	00a584b3          	add	s1,a1,a0
   894fa:	00061517          	auipc	a0,0x61
   894fe:	1ea50593          	addi	a1,a0,490 # ea6e4 <_ZZL13pch_open_fileP10cpp_readerP9_cpp_filePbE9extension+0x22c9>
   89502:	8526                	mv	a0,s1
   89504:	8d2e                	mv	s10,a1
   89506:	96b8a0ef          	jal	13e70 <strcmp@plt>
   8950a:	8c26                	mv	s8,s1
   8950c:	c155                	beqz	a0,895b0 <elf_add+0x72e>
   8950e:	00061517          	auipc	a0,0x61
   89512:	1e250593          	addi	a1,a0,482 # ea6f0 <_ZZL13pch_open_fileP10cpp_readerP9_cpp_filePbE9extension+0x22d5>
   89516:	8526                	mv	a0,s1
   89518:	9598a0ef          	jal	13e70 <strcmp@plt>
   8951c:	59810593          	addi	a1,sp,1432
   89520:	c951                	beqz	a0,895b4 <elf_add+0x732>
   89522:	00061517          	auipc	a0,0x61
   89526:	1da50593          	addi	a1,a0,474 # ea6fc <_ZZL13pch_open_fileP10cpp_readerP9_cpp_filePbE9extension+0x22e1>
   8952a:	8562                	mv	a0,s8
   8952c:	9458a0ef          	jal	13e70 <strcmp@plt>
   89530:	5b810593          	addi	a1,sp,1464
   89534:	c141                	beqz	a0,895b4 <elf_add+0x732>
   89536:	00061517          	auipc	a0,0x61
   8953a:	1d450593          	addi	a1,a0,468 # ea70a <_ZZL13pch_open_fileP10cpp_readerP9_cpp_filePbE9extension+0x22ef>
   8953e:	8562                	mv	a0,s8
   89540:	9318a0ef          	jal	13e70 <strcmp@plt>
   89544:	5d810593          	addi	a1,sp,1496
   89548:	c535                	beqz	a0,895b4 <elf_add+0x732>
   8954a:	00061517          	auipc	a0,0x61
   8954e:	1ce50593          	addi	a1,a0,462 # ea718 <_ZZL13pch_open_fileP10cpp_readerP9_cpp_filePbE9extension+0x22fd>
   89552:	8562                	mv	a0,s8
   89554:	91d8a0ef          	jal	13e70 <strcmp@plt>
   89558:	5f810593          	addi	a1,sp,1528
   8955c:	cd21                	beqz	a0,895b4 <elf_add+0x732>
   8955e:	00061517          	auipc	a0,0x61
   89562:	1c550593          	addi	a1,a0,453 # ea723 <_ZZL13pch_open_fileP10cpp_readerP9_cpp_filePbE9extension+0x2308>
   89566:	8562                	mv	a0,s8
   89568:	9098a0ef          	jal	13e70 <strcmp@plt>
   8956c:	61810593          	addi	a1,sp,1560
   89570:	c131                	beqz	a0,895b4 <elf_add+0x732>
   89572:	00061517          	auipc	a0,0x61
   89576:	1bd50593          	addi	a1,a0,445 # ea72f <_ZZL13pch_open_fileP10cpp_readerP9_cpp_filePbE9extension+0x2314>
   8957a:	8562                	mv	a0,s8
   8957c:	8f58a0ef          	jal	13e70 <strcmp@plt>
   89580:	63810593          	addi	a1,sp,1592
   89584:	c905                	beqz	a0,895b4 <elf_add+0x732>
   89586:	00061517          	auipc	a0,0x61
   8958a:	1bc50593          	addi	a1,a0,444 # ea742 <_ZZL13pch_open_fileP10cpp_readerP9_cpp_filePbE9extension+0x2327>
   8958e:	8562                	mv	a0,s8
   89590:	8e18a0ef          	jal	13e70 <strcmp@plt>
   89594:	65810593          	addi	a1,sp,1624
   89598:	cd11                	beqz	a0,895b4 <elf_add+0x732>
   8959a:	00061517          	auipc	a0,0x61
   8959e:	1b850593          	addi	a1,a0,440 # ea752 <_ZZL13pch_open_fileP10cpp_readerP9_cpp_filePbE9extension+0x2337>
   895a2:	8562                	mv	a0,s8
   895a4:	8cd8a0ef          	jal	13e70 <strcmp@plt>
   895a8:	67810593          	addi	a1,sp,1656
   895ac:	ed11                	bnez	a0,895c8 <elf_add+0x746>
   895ae:	a019                	j	895b4 <elf_add+0x732>
   895b0:	57810593          	addi	a1,sp,1400
   895b4:	ff843503          	ld	a0,-8(s0)
   895b8:	6010                	ld	a2,0(s0)
   895ba:	e188                	sd	a0,0(a1)
   895bc:	e590                	sd	a2,8(a1)
   895be:	fe842503          	lw	a0,-24(s0)
   895c2:	1552                	slli	a0,a0,0x34
   895c4:	917d                	srli	a0,a0,0x3f
   895c6:	cd88                	sw	a0,24(a1)
   895c8:	86e2                	mv	a3,s8
   895ca:	000c4503          	lbu	a0,0(s8)
   895ce:	02e00593          	li	a1,46
   895d2:	0eb51163          	bne	a0,a1,896b4 <elf_add+0x832>
   895d6:	0016c503          	lbu	a0,1(a3)
   895da:	07a00593          	li	a1,122
   895de:	0cb51b63          	bne	a0,a1,896b4 <elf_add+0x832>
   895e2:	00268493          	addi	s1,a3,2
   895e6:	001d0593          	addi	a1,s10,1
   895ea:	8526                	mv	a0,s1
   895ec:	8858a0ef          	jal	13e70 <strcmp@plt>
   895f0:	c955                	beqz	a0,896a4 <elf_add+0x822>
   895f2:	00061517          	auipc	a0,0x61
   895f6:	0ff50593          	addi	a1,a0,255 # ea6f1 <_ZZL13pch_open_fileP10cpp_readerP9_cpp_filePbE9extension+0x22d6>
   895fa:	8526                	mv	a0,s1
   895fc:	8758a0ef          	jal	13e70 <strcmp@plt>
   89600:	47810593          	addi	a1,sp,1144
   89604:	86e2                	mv	a3,s8
   89606:	c155                	beqz	a0,896aa <elf_add+0x828>
   89608:	00061517          	auipc	a0,0x61
   8960c:	0f550593          	addi	a1,a0,245 # ea6fd <_ZZL13pch_open_fileP10cpp_readerP9_cpp_filePbE9extension+0x22e2>
   89610:	8526                	mv	a0,s1
   89612:	85f8a0ef          	jal	13e70 <strcmp@plt>
   89616:	86e2                	mv	a3,s8
   89618:	49810593          	addi	a1,sp,1176
   8961c:	c559                	beqz	a0,896aa <elf_add+0x828>
   8961e:	00061517          	auipc	a0,0x61
   89622:	0ed50593          	addi	a1,a0,237 # ea70b <_ZZL13pch_open_fileP10cpp_readerP9_cpp_filePbE9extension+0x22f0>
   89626:	8526                	mv	a0,s1
   89628:	8498a0ef          	jal	13e70 <strcmp@plt>
   8962c:	86e2                	mv	a3,s8
   8962e:	4b810593          	addi	a1,sp,1208
   89632:	cd25                	beqz	a0,896aa <elf_add+0x828>
   89634:	00061517          	auipc	a0,0x61
   89638:	0e550593          	addi	a1,a0,229 # ea719 <_ZZL13pch_open_fileP10cpp_readerP9_cpp_filePbE9extension+0x22fe>
   8963c:	8526                	mv	a0,s1
   8963e:	8338a0ef          	jal	13e70 <strcmp@plt>
   89642:	86e2                	mv	a3,s8
   89644:	4d810593          	addi	a1,sp,1240
   89648:	c12d                	beqz	a0,896aa <elf_add+0x828>
   8964a:	00061517          	auipc	a0,0x61
   8964e:	0da50593          	addi	a1,a0,218 # ea724 <_ZZL13pch_open_fileP10cpp_readerP9_cpp_filePbE9extension+0x2309>
   89652:	8526                	mv	a0,s1
   89654:	81d8a0ef          	jal	13e70 <strcmp@plt>
   89658:	86e2                	mv	a3,s8
   8965a:	4f810593          	addi	a1,sp,1272
   8965e:	c531                	beqz	a0,896aa <elf_add+0x828>
   89660:	00061517          	auipc	a0,0x61
   89664:	0d050593          	addi	a1,a0,208 # ea730 <_ZZL13pch_open_fileP10cpp_readerP9_cpp_filePbE9extension+0x2315>
   89668:	8526                	mv	a0,s1
   8966a:	8078a0ef          	jal	13e70 <strcmp@plt>
   8966e:	86e2                	mv	a3,s8
   89670:	51810593          	addi	a1,sp,1304
   89674:	c91d                	beqz	a0,896aa <elf_add+0x828>
   89676:	00061517          	auipc	a0,0x61
   8967a:	0cd50593          	addi	a1,a0,205 # ea743 <_ZZL13pch_open_fileP10cpp_readerP9_cpp_filePbE9extension+0x2328>
   8967e:	8526                	mv	a0,s1
   89680:	ff08a0ef          	jal	13e70 <strcmp@plt>
   89684:	86e2                	mv	a3,s8
   89686:	53810593          	addi	a1,sp,1336
   8968a:	c105                	beqz	a0,896aa <elf_add+0x828>
   8968c:	00061517          	auipc	a0,0x61
   89690:	0c750593          	addi	a1,a0,199 # ea753 <_ZZL13pch_open_fileP10cpp_readerP9_cpp_filePbE9extension+0x2338>
   89694:	8526                	mv	a0,s1
   89696:	fda8a0ef          	jal	13e70 <strcmp@plt>
   8969a:	86e2                	mv	a3,s8
   8969c:	55810593          	addi	a1,sp,1368
   896a0:	e911                	bnez	a0,896b4 <elf_add+0x832>
   896a2:	a021                	j	896aa <elf_add+0x828>
   896a4:	45810593          	addi	a1,sp,1112
   896a8:	86e2                	mv	a3,s8
   896aa:	ff843503          	ld	a0,-8(s0)
   896ae:	6010                	ld	a2,0(s0)
   896b0:	e188                	sd	a0,0(a1)
   896b2:	e590                	sd	a2,8(a1)
   896b4:	754a                	ld	a0,176(sp)
   896b6:	00a03533          	snez	a0,a0
   896ba:	758e                	ld	a1,224(sp)
   896bc:	8d4d                	or	a0,a0,a1
   896be:	e14d                	bnez	a0,89760 <elf_add+0x8de>
   896c0:	00061517          	auipc	a0,0x61
   896c4:	f8e50593          	addi	a1,a0,-114 # ea64e <_ZZL13pch_open_fileP10cpp_readerP9_cpp_filePbE9extension+0x2233>
   896c8:	8536                	mv	a0,a3
   896ca:	fa68a0ef          	jal	13e70 <strcmp@plt>
   896ce:	c119                	beqz	a0,896d4 <elf_add+0x852>
   896d0:	f902                	sd	zero,176(sp)
   896d2:	a071                	j	8975e <elf_add+0x8dc>
   896d4:	ff843703          	ld	a4,-8(s0)
   896d8:	601c                	ld	a5,0(s0)
   896da:	3f810e13          	addi	t3,sp,1016
   896de:	8566                	mv	a0,s9
   896e0:	85ca                	mv	a1,s2
   896e2:	7632                	ld	a2,296(sp)
   896e4:	76d2                	ld	a3,304(sp)
   896e6:	885e                	mv	a6,s7
   896e8:	88da                	mv	a7,s6
   896ea:	284020ef          	jal	8b96e <elf_get_view>
   896ee:	e9d2                	sd	s4,208(sp)
   896f0:	68050f63          	beqz	a0,89d8e <elf_add+0xf0c>
   896f4:	3f813483          	ld	s1,1016(sp)
   896f8:	4488                	lw	a0,8(s1)
   896fa:	458d                	li	a1,3
   896fc:	86e2                	mv	a3,s8
   896fe:	02b51e63          	bne	a0,a1,8973a <elf_add+0x8b8>
   89702:	4088                	lw	a0,0(s1)
   89704:	4591                	li	a1,4
   89706:	02b51a63          	bne	a0,a1,8973a <elf_add+0x8b8>
   8970a:	00c48513          	addi	a0,s1,12
   8970e:	00061597          	auipc	a1,0x61
   89712:	f5358593          	addi	a1,a1,-173 # ea661 <_ZZL13pch_open_fileP10cpp_readerP9_cpp_filePbE9extension+0x2246>
   89716:	4611                	li	a2,4
   89718:	f398a0ef          	jal	14650 <strncmp@plt>
   8971c:	c119                	beqz	a0,89722 <elf_add+0x8a0>
   8971e:	86e2                	mv	a3,s8
   89720:	a829                	j	8973a <elf_add+0x8b8>
   89722:	40c8                	lw	a0,4(s1)
   89724:	600c                	ld	a1,0(s0)
   89726:	01050613          	addi	a2,a0,16
   8972a:	1602                	slli	a2,a2,0x20
   8972c:	9201                	srli	a2,a2,0x20
   8972e:	86e2                	mv	a3,s8
   89730:	00b66563          	bltu	a2,a1,8973a <elf_add+0x8b8>
   89734:	04c1                	addi	s1,s1,16
   89736:	e4a6                	sd	s1,72(sp)
   89738:	e92a                	sd	a0,144(sp)
   8973a:	6a4e                	ld	s4,208(sp)
   8973c:	662e                	ld	a2,200(sp)
   8973e:	16060d63          	beqz	a2,898b8 <elf_add+0xa36>
   89742:	45ca                	lw	a1,144(sp)
   89744:	6526                	ld	a0,72(sp)
   89746:	70c59263          	bne	a1,a2,89e4a <elf_add+0xfc8>
   8974a:	658e                	ld	a1,192(sp)
   8974c:	6606                	ld	a2,64(sp)
   8974e:	a438a0ef          	jal	14190 <bcmp@plt>
   89752:	4585                	li	a1,1
   89754:	f92e                	sd	a1,176(sp)
   89756:	70051063          	bnez	a0,89e56 <elf_add+0xfd4>
   8975a:	652e                	ld	a0,200(sp)
   8975c:	e92a                	sd	a0,144(sp)
   8975e:	86e2                	mv	a3,s8
   89760:	7572                	ld	a0,312(sp)
   89762:	01556533          	or	a0,a0,s5
   89766:	2501                	sext.w	a0,a0
   89768:	ed29                	bnez	a0,897c2 <elf_add+0x940>
   8976a:	00061517          	auipc	a0,0x61
   8976e:	efb50593          	addi	a1,a0,-261 # ea665 <_ZZL13pch_open_fileP10cpp_readerP9_cpp_filePbE9extension+0x224a>
   89772:	8536                	mv	a0,a3
   89774:	efc8a0ef          	jal	13e70 <strcmp@plt>
   89778:	c119                	beqz	a0,8977e <elf_add+0x8fc>
   8977a:	4a81                	li	s5,0
   8977c:	a091                	j	897c0 <elf_add+0x93e>
   8977e:	ff843703          	ld	a4,-8(s0)
   89782:	601c                	ld	a5,0(s0)
   89784:	3d810e13          	addi	t3,sp,984
   89788:	8566                	mv	a0,s9
   8978a:	85ca                	mv	a1,s2
   8978c:	7632                	ld	a2,296(sp)
   8978e:	76d2                	ld	a3,304(sp)
   89790:	885e                	mv	a6,s7
   89792:	88da                	mv	a7,s6
   89794:	1da020ef          	jal	8b96e <elf_get_view>
   89798:	60050063          	beqz	a0,89d98 <elf_add+0xf16>
   8979c:	3d813d03          	ld	s10,984(sp)
   897a0:	6004                	ld	s1,0(s0)
   897a2:	856a                	mv	a0,s10
   897a4:	85a6                	mv	a1,s1
   897a6:	c4b8a0ef          	jal	143f0 <strnlen@plt>
   897aa:	050d                	addi	a0,a0,3
   897ac:	9971                	andi	a0,a0,-4
   897ae:	00450593          	addi	a1,a0,4
   897b2:	4a85                	li	s5,1
   897b4:	00b4e663          	bltu	s1,a1,897c0 <elf_add+0x93e>
   897b8:	956a                	add	a0,a0,s10
   897ba:	4108                	lw	a0,0(a0)
   897bc:	f0aa                	sd	a0,96(sp)
   897be:	f4ea                	sd	s10,104(sp)
   897c0:	86e2                	mv	a3,s8
   897c2:	756a                	ld	a0,184(sp)
   897c4:	c501                	beqz	a0,897cc <elf_add+0x94a>
   897c6:	4505                	li	a0,1
   897c8:	fd2a                	sd	a0,184(sp)
   897ca:	a0a5                	j	89832 <elf_add+0x9b0>
   897cc:	00061517          	auipc	a0,0x61
   897d0:	ea850593          	addi	a1,a0,-344 # ea674 <_ZZL13pch_open_fileP10cpp_readerP9_cpp_filePbE9extension+0x2259>
   897d4:	8536                	mv	a0,a3
   897d6:	e9a8a0ef          	jal	13e70 <strcmp@plt>
   897da:	c501                	beqz	a0,897e2 <elf_add+0x960>
   897dc:	fd02                	sd	zero,184(sp)
   897de:	86e2                	mv	a3,s8
   897e0:	a889                	j	89832 <elf_add+0x9b0>
   897e2:	ff843703          	ld	a4,-8(s0)
   897e6:	601c                	ld	a5,0(s0)
   897e8:	3b810e13          	addi	t3,sp,952
   897ec:	8566                	mv	a0,s9
   897ee:	85ca                	mv	a1,s2
   897f0:	7632                	ld	a2,296(sp)
   897f2:	76d2                	ld	a3,304(sp)
   897f4:	885e                	mv	a6,s7
   897f6:	88da                	mv	a7,s6
   897f8:	176020ef          	jal	8b96e <elf_get_view>
   897fc:	62050f63          	beqz	a0,89e3a <elf_add+0xfb8>
   89800:	85a2                	mv	a1,s0
   89802:	8d52                	mv	s10,s4
   89804:	3b813403          	ld	s0,952(sp)
   89808:	8a2e                	mv	s4,a1
   8980a:	6184                	ld	s1,0(a1)
   8980c:	8522                	mv	a0,s0
   8980e:	85a6                	mv	a1,s1
   89810:	be18a0ef          	jal	143f0 <strnlen@plt>
   89814:	f8a2                	sd	s0,112(sp)
   89816:	00957963          	bgeu	a0,s1,89828 <elf_add+0x9a6>
   8981a:	0505                	addi	a0,a0,1
   8981c:	00a405b3          	add	a1,s0,a0
   89820:	ecae                	sd	a1,88(sp)
   89822:	40a4853b          	subw	a0,s1,a0
   89826:	e8aa                	sd	a0,80(sp)
   89828:	86e2                	mv	a3,s8
   8982a:	4505                	li	a0,1
   8982c:	fd2a                	sd	a0,184(sp)
   8982e:	8452                	mv	s0,s4
   89830:	8a6a                	mv	s4,s10
   89832:	7572                	ld	a0,312(sp)
   89834:	01456533          	or	a0,a0,s4
   89838:	2501                	sext.w	a0,a0
   8983a:	ed15                	bnez	a0,89876 <elf_add+0x9f4>
   8983c:	00061517          	auipc	a0,0x61
   89840:	e4a50593          	addi	a1,a0,-438 # ea686 <_ZZL13pch_open_fileP10cpp_readerP9_cpp_filePbE9extension+0x226b>
   89844:	8536                	mv	a0,a3
   89846:	e2a8a0ef          	jal	13e70 <strcmp@plt>
   8984a:	c119                	beqz	a0,89850 <elf_add+0x9ce>
   8984c:	4a01                	li	s4,0
   8984e:	a01d                	j	89874 <elf_add+0x9f2>
   89850:	ff843703          	ld	a4,-8(s0)
   89854:	601c                	ld	a5,0(s0)
   89856:	39810e13          	addi	t3,sp,920
   8985a:	8566                	mv	a0,s9
   8985c:	85ca                	mv	a1,s2
   8985e:	7632                	ld	a2,296(sp)
   89860:	76d2                	ld	a3,304(sp)
   89862:	885e                	mv	a6,s7
   89864:	88da                	mv	a7,s6
   89866:	108020ef          	jal	8b96e <elf_get_view>
   8986a:	52050c63          	beqz	a0,89da2 <elf_add+0xf20>
   8986e:	6008                	ld	a0,0(s0)
   89870:	fcaa                	sd	a0,120(sp)
   89872:	4a05                	li	s4,1
   89874:	86e2                	mv	a3,s8
   89876:	656e                	ld	a0,216(sp)
   89878:	c40504e3          	beqz	a0,894c0 <elf_add+0x63e>
   8987c:	fe442503          	lw	a0,-28(s0)
   89880:	4585                	li	a1,1
   89882:	c2b51fe3          	bne	a0,a1,894c0 <elf_add+0x63e>
   89886:	00061517          	auipc	a0,0x61
   8988a:	e0f50593          	addi	a1,a0,-497 # ea695 <_ZZL13pch_open_fileP10cpp_readerP9_cpp_filePbE9extension+0x227a>
   8988e:	8536                	mv	a0,a3
   89890:	de08a0ef          	jal	13e70 <strcmp@plt>
   89894:	c20516e3          	bnez	a0,894c0 <elf_add+0x63e>
   89898:	ff843703          	ld	a4,-8(s0)
   8989c:	601c                	ld	a5,0(s0)
   8989e:	8566                	mv	a0,s9
   898a0:	85ca                	mv	a1,s2
   898a2:	7632                	ld	a2,296(sp)
   898a4:	76d2                	ld	a3,304(sp)
   898a6:	885e                	mv	a6,s7
   898a8:	88da                	mv	a7,s6
   898aa:	21810e13          	addi	t3,sp,536
   898ae:	0c0020ef          	jal	8b96e <elf_get_view>
   898b2:	be0519e3          	bnez	a0,894a4 <elf_add+0x622>
   898b6:	a365                	j	89e5e <elf_add+0xfdc>
   898b8:	4505                	li	a0,1
   898ba:	f92a                	sd	a0,176(sp)
   898bc:	b555                	j	89760 <elf_add+0x8de>
   898be:	754a                	ld	a0,176(sp)
   898c0:	c911                	beqz	a0,898d4 <elf_add+0xa52>
   898c2:	41012503          	lw	a0,1040(sp)
   898c6:	c519                	beqz	a0,898d4 <elf_add+0xa52>
   898c8:	1fac                	addi	a1,sp,1016
   898ca:	8566                	mv	a0,s9
   898cc:	865e                	mv	a2,s7
   898ce:	86da                	mv	a3,s6
   898d0:	1df020ef          	jal	8c2ae <backtrace_release_view>
   898d4:	7626                	ld	a2,104(sp)
   898d6:	c651                	beqz	a2,89962 <elf_add+0xae0>
   898d8:	8566                	mv	a0,s9
   898da:	75ce                	ld	a1,240(sp)
   898dc:	7686                	ld	a3,96(sp)
   898de:	875e                	mv	a4,s7
   898e0:	87da                	mv	a5,s6
   898e2:	436020ef          	jal	8bd18 <elf_open_debugfile_by_debuglink>
   898e6:	06054e63          	bltz	a0,89962 <elf_add+0xae0>
   898ea:	842a                	mv	s0,a0
   898ec:	3f012503          	lw	a0,1008(sp)
   898f0:	c519                	beqz	a0,898fe <elf_add+0xa7c>
   898f2:	0fac                	addi	a1,sp,984
   898f4:	8566                	mv	a0,s9
   898f6:	865e                	mv	a2,s7
   898f8:	86da                	mv	a3,s6
   898fa:	1b5020ef          	jal	8c2ae <backtrace_release_view>
   898fe:	79ee                	ld	s3,248(sp)
   89900:	6ab2                	ld	s5,264(sp)
   89902:	64d2                	ld	s1,272(sp)
   89904:	6a12                	ld	s4,256(sp)
   89906:	756a                	ld	a0,184(sp)
   89908:	c911                	beqz	a0,8991c <elf_add+0xa9a>
   8990a:	3d012503          	lw	a0,976(sp)
   8990e:	c519                	beqz	a0,8991c <elf_add+0xa9a>
   89910:	1f2c                	addi	a1,sp,952
   89912:	8566                	mv	a0,s9
   89914:	865e                	mv	a2,s7
   89916:	86da                	mv	a3,s6
   89918:	197020ef          	jal	8c2ae <backtrace_release_view>
   8991c:	f002                	sd	zero,32(sp)
   8991e:	4505                	li	a0,1
   89920:	0005b597          	auipc	a1,0x5b
   89924:	63e58593          	addi	a1,a1,1598 # e4f5e <_ZZ13trim_filenamePKcE9this_file+0x1a44>
   89928:	e002                	sd	zero,0(sp)
   8992a:	e402                	sd	zero,8(sp)
   8992c:	e82a                	sd	a0,16(sp)
   8992e:	ec02                	sd	zero,24(sp)
   89930:	8566                	mv	a0,s9
   89932:	8622                	mv	a2,s0
   89934:	4681                	li	a3,0
   89936:	4701                	li	a4,0
   89938:	87a6                	mv	a5,s1
   8993a:	886e                	mv	a6,s11
   8993c:	88de                	mv	a7,s7
   8993e:	8e5a                	mv	t3,s6
   89940:	8ed6                	mv	t4,s5
   89942:	8f52                	mv	t5,s4
   89944:	8fce                	mv	t6,s3
   89946:	d3cff0ef          	jal	88e82 <elf_add>
   8994a:	08054863          	bltz	a0,899da <elf_add+0xb58>
   8994e:	a60942e3          	bltz	s2,893b2 <elf_add+0x530>
   89952:	89aa                	mv	s3,a0
   89954:	854a                	mv	a0,s2
   89956:	85de                	mv	a1,s7
   89958:	865a                	mv	a2,s6
   8995a:	91cfc0ef          	jal	85a76 <backtrace_close>
   8995e:	854e                	mv	a0,s3
   89960:	bc89                	j	893b2 <elf_add+0x530>
   89962:	7572                	ld	a0,312(sp)
   89964:	c911                	beqz	a0,89978 <elf_add+0xaf6>
   89966:	3f012503          	lw	a0,1008(sp)
   8996a:	c519                	beqz	a0,89978 <elf_add+0xaf6>
   8996c:	0fac                	addi	a1,sp,984
   8996e:	8566                	mv	a0,s9
   89970:	865e                	mv	a2,s7
   89972:	86da                	mv	a3,s6
   89974:	13b020ef          	jal	8c2ae <backtrace_release_view>
   89978:	f682                	sd	zero,360(sp)
   8997a:	7646                	ld	a2,112(sp)
   8997c:	16060f63          	beqz	a2,89afa <elf_add+0xc78>
   89980:	8566                	mv	a0,s9
   89982:	75ce                	ld	a1,240(sp)
   89984:	4681                	li	a3,0
   89986:	875e                	mv	a4,s7
   89988:	87da                	mv	a5,s6
   8998a:	38e020ef          	jal	8bd18 <elf_open_debugfile_by_debuglink>
   8998e:	16054663          	bltz	a0,89afa <elf_add+0xc78>
   89992:	842a                	mv	s0,a0
   89994:	6546                	ld	a0,80(sp)
   89996:	f02a                	sd	a0,32(sp)
   89998:	4505                	li	a0,1
   8999a:	12ac                	addi	a1,sp,360
   8999c:	e02e                	sd	a1,0(sp)
   8999e:	e402                	sd	zero,8(sp)
   899a0:	e82a                	sd	a0,16(sp)
   899a2:	6566                	ld	a0,88(sp)
   899a4:	ec2a                	sd	a0,24(sp)
   899a6:	8566                	mv	a0,s9
   899a8:	75ce                	ld	a1,240(sp)
   899aa:	8622                	mv	a2,s0
   899ac:	4681                	li	a3,0
   899ae:	4701                	li	a4,0
   899b0:	67d2                	ld	a5,272(sp)
   899b2:	886e                	mv	a6,s11
   899b4:	88de                	mv	a7,s7
   899b6:	8e5a                	mv	t3,s6
   899b8:	6eb2                	ld	t4,264(sp)
   899ba:	6f12                	ld	t5,256(sp)
   899bc:	7fee                	ld	t6,248(sp)
   899be:	cc4ff0ef          	jal	88e82 <elf_add>
   899c2:	3d012583          	lw	a1,976(sp)
   899c6:	84aa                	mv	s1,a0
   899c8:	c599                	beqz	a1,899d6 <elf_add+0xb54>
   899ca:	1f2c                	addi	a1,sp,952
   899cc:	8566                	mv	a0,s9
   899ce:	865e                	mv	a2,s7
   899d0:	86da                	mv	a3,s6
   899d2:	0dd020ef          	jal	8c2ae <backtrace_release_view>
   899d6:	1204dd63          	bgez	s1,89b10 <elf_add+0xc8e>
   899da:	8522                	mv	a0,s0
   899dc:	85de                	mv	a1,s7
   899de:	865a                	mv	a2,s6
   899e0:	896fc0ef          	jal	85a76 <backtrace_close>
   899e4:	557d                	li	a0,-1
   899e6:	b2f1                	j	893b2 <elf_add+0x530>
   899e8:	fe56                	sd	s5,312(sp)
   899ea:	6d8a                	ld	s11,128(sp)
   899ec:	7c6a                	ld	s8,184(sp)
   899ee:	e9d2                	sd	s4,208(sp)
   899f0:	00061517          	auipc	a0,0x61
   899f4:	c4050593          	addi	a1,a0,-960 # ea630 <_ZZL13pch_open_fileP10cpp_readerP9_cpp_filePbE9extension+0x2215>
   899f8:	a4f1                	j	89cc4 <elf_add+0xe42>
   899fa:	fe56                	sd	s5,312(sp)
   899fc:	6df2                	ld	s11,280(sp)
   899fe:	650a                	ld	a0,128(sp)
   89a00:	c111                	beqz	a0,89a04 <elf_add+0xb82>
   89a02:	6d8a                	ld	s11,128(sp)
   89a04:	6aa6                	ld	s5,72(sp)
   89a06:	652a                	ld	a0,136(sp)
   89a08:	c111                	beqz	a0,89a0c <elf_add+0xb8a>
   89a0a:	ed2a                	sd	a0,152(sp)
   89a0c:	650a                	ld	a0,128(sp)
   89a0e:	00153d13          	seqz	s10,a0
   89a12:	656a                	ld	a0,152(sp)
   89a14:	9e050ce3          	beqz	a0,8940c <elf_add+0x58a>
   89a18:	7c6a                	ld	s8,184(sp)
   89a1a:	e9d2                	sd	s4,208(sp)
   89a1c:	157d                	addi	a0,a0,-1
   89a1e:	1502                	slli	a0,a0,0x20
   89a20:	8169                	srli	a0,a0,0x1a
   89a22:	7a62                	ld	s4,56(sp)
   89a24:	9a2a                	add	s4,s4,a0
   89a26:	028a2483          	lw	s1,40(s4)
   89a2a:	7542                	ld	a0,48(sp)
   89a2c:	28a4f863          	bgeu	s1,a0,89cbc <elf_add+0xe3a>
   89a30:	018a3703          	ld	a4,24(s4)
   89a34:	020a3783          	ld	a5,32(s4)
   89a38:	43810e13          	addi	t3,sp,1080
   89a3c:	8566                	mv	a0,s9
   89a3e:	85ca                	mv	a1,s2
   89a40:	7632                	ld	a2,296(sp)
   89a42:	76d2                	ld	a3,304(sp)
   89a44:	885e                	mv	a6,s7
   89a46:	88da                	mv	a7,s6
   89a48:	727010ef          	jal	8b96e <elf_get_view>
   89a4c:	4a85                	li	s5,1
   89a4e:	26050f63          	beqz	a0,89ccc <elf_add+0xe4a>
   89a52:	f5ea                	sd	s10,232(sp)
   89a54:	14fd                	addi	s1,s1,-1
   89a56:	1482                	slli	s1,s1,0x20
   89a58:	80e9                	srli	s1,s1,0x1a
   89a5a:	7562                	ld	a0,56(sp)
   89a5c:	94aa                	add	s1,s1,a0
   89a5e:	6c98                	ld	a4,24(s1)
   89a60:	709c                	ld	a5,32(s1)
   89a62:	41810e13          	addi	t3,sp,1048
   89a66:	8566                	mv	a0,s9
   89a68:	e2ca                	sd	s2,320(sp)
   89a6a:	85ca                	mv	a1,s2
   89a6c:	7632                	ld	a2,296(sp)
   89a6e:	76d2                	ld	a3,304(sp)
   89a70:	885e                	mv	a6,s7
   89a72:	88da                	mv	a7,s6
   89a74:	6fb010ef          	jal	8b96e <elf_get_view>
   89a78:	100502e3          	beqz	a0,8a37c <elf_add+0x14fa>
   89a7c:	45e1                	li	a1,24
   89a7e:	8d66                	mv	s10,s9
   89a80:	8566                	mv	a0,s9
   89a82:	eede                	sd	s7,344(sp)
   89a84:	865e                	mv	a2,s7
   89a86:	895a                	mv	s2,s6
   89a88:	86da                	mv	a3,s6
   89a8a:	a8bfb0ef          	jal	85514 <backtrace_alloc>
   89a8e:	0c0505e3          	beqz	a0,8a358 <elf_add+0x14d6>
   89a92:	842a                	mv	s0,a0
   89a94:	43813603          	ld	a2,1080(sp)
   89a98:	41813703          	ld	a4,1048(sp)
   89a9c:	020a3683          	ld	a3,32(s4)
   89aa0:	709c                	ld	a5,32(s1)
   89aa2:	856a                	mv	a0,s10
   89aa4:	65d2                	ld	a1,272(sp)
   89aa6:	6876                	ld	a6,344(sp)
   89aa8:	88ca                	mv	a7,s2
   89aaa:	8e22                	mv	t3,s0
   89aac:	8eee                	mv	t4,s11
   89aae:	70f010ef          	jal	8b9bc <elf_initialize_syminfo>
   89ab2:	0a050ae3          	beqz	a0,8a366 <elf_add+0x14e4>
   89ab6:	45012503          	lw	a0,1104(sp)
   89aba:	c901                	beqz	a0,89aca <elf_add+0xc48>
   89abc:	43810593          	addi	a1,sp,1080
   89ac0:	856a                	mv	a0,s10
   89ac2:	6676                	ld	a2,344(sp)
   89ac4:	86ca                	mv	a3,s2
   89ac6:	7e8020ef          	jal	8c2ae <backtrace_release_view>
   89aca:	4505                	li	a0,1
   89acc:	6592                	ld	a1,256(sp)
   89ace:	c188                	sw	a0,0(a1)
   89ad0:	008d2583          	lw	a1,8(s10)
   89ad4:	030d0513          	addi	a0,s10,48
   89ad8:	1a058763          	beqz	a1,89c86 <elf_add+0xe04>
   89adc:	85aa                	mv	a1,a0
   89ade:	862e                	mv	a2,a1
   89ae0:	618c                	ld	a1,0(a1)
   89ae2:	0230000f          	fence	r,rw
   89ae6:	fde5                	bnez	a1,89ade <elf_add+0xc5c>
   89ae8:	160636af          	lr.d.aqrl	a3,(a2)
   89aec:	e681                	bnez	a3,89af4 <elf_add+0xc72>
   89aee:	1a8635af          	sc.d.rl	a1,s0,(a2)
   89af2:	f9fd                	bnez	a1,89ae8 <elf_add+0xc66>
   89af4:	85aa                	mv	a1,a0
   89af6:	f6e5                	bnez	a3,89ade <elf_add+0xc5c>
   89af8:	aa59                	j	89c8e <elf_add+0xe0c>
   89afa:	756a                	ld	a0,184(sp)
   89afc:	c911                	beqz	a0,89b10 <elf_add+0xc8e>
   89afe:	3d012503          	lw	a0,976(sp)
   89b02:	c519                	beqz	a0,89b10 <elf_add+0xc8e>
   89b04:	1f2c                	addi	a1,sp,952
   89b06:	8566                	mv	a0,s9
   89b08:	865e                	mv	a2,s7
   89b0a:	86da                	mv	a3,s6
   89b0c:	7a2020ef          	jal	8c2ae <backtrace_release_view>
   89b10:	060a0a63          	beqz	s4,89b84 <elf_add+0xd02>
   89b14:	39813583          	ld	a1,920(sp)
   89b18:	0f1c                	addi	a5,sp,912
   89b1a:	38810813          	addi	a6,sp,904
   89b1e:	8566                	mv	a0,s9
   89b20:	7666                	ld	a2,120(sp)
   89b22:	86de                	mv	a3,s7
   89b24:	875a                	mv	a4,s6
   89b26:	8b6fe0ef          	jal	87bdc <elf_uncompress_lzma>
   89b2a:	3b012583          	lw	a1,944(sp)
   89b2e:	842a                	mv	s0,a0
   89b30:	c599                	beqz	a1,89b3e <elf_add+0xcbc>
   89b32:	0f2c                	addi	a1,sp,920
   89b34:	8566                	mv	a0,s9
   89b36:	865e                	mv	a2,s7
   89b38:	86da                	mv	a3,s6
   89b3a:	774020ef          	jal	8c2ae <backtrace_release_view>
   89b3e:	c039                	beqz	s0,89b84 <elf_add+0xd02>
   89b40:	39013683          	ld	a3,912(sp)
   89b44:	38813703          	ld	a4,904(sp)
   89b48:	f002                	sd	zero,32(sp)
   89b4a:	567d                	li	a2,-1
   89b4c:	e002                	sd	zero,0(sp)
   89b4e:	e402                	sd	zero,8(sp)
   89b50:	e802                	sd	zero,16(sp)
   89b52:	ec02                	sd	zero,24(sp)
   89b54:	8566                	mv	a0,s9
   89b56:	75ce                	ld	a1,240(sp)
   89b58:	67d2                	ld	a5,272(sp)
   89b5a:	886e                	mv	a6,s11
   89b5c:	88de                	mv	a7,s7
   89b5e:	8e5a                	mv	t3,s6
   89b60:	6eb2                	ld	t4,264(sp)
   89b62:	6f12                	ld	t5,256(sp)
   89b64:	7fee                	ld	t6,248(sp)
   89b66:	b1cff0ef          	jal	88e82 <elf_add>
   89b6a:	012565b3          	or	a1,a0,s2
   89b6e:	8405c2e3          	bltz	a1,893b2 <elf_add+0x530>
   89b72:	84aa                	mv	s1,a0
   89b74:	854a                	mv	a0,s2
   89b76:	85de                	mv	a1,s7
   89b78:	865a                	mv	a2,s6
   89b7a:	efdfb0ef          	jal	85a76 <backtrace_close>
   89b7e:	8526                	mv	a0,s1
   89b80:	833ff06f          	j	893b2 <elf_add+0x530>
   89b84:	02098463          	beqz	s3,89bac <elf_add+0xd2a>
   89b88:	6572                	ld	a0,280(sp)
   89b8a:	000d1363          	bnez	s10,89b90 <elf_add+0xd0e>
   89b8e:	650a                	ld	a0,128(sp)
   89b90:	5908                	lw	a0,48(a0)
   89b92:	cd01                	beqz	a0,89baa <elf_add+0xd28>
   89b94:	000d1463          	bnez	s10,89b9c <elf_add+0xd1a>
   89b98:	650a                	ld	a0,128(sp)
   89b9a:	ee2a                	sd	a0,280(sp)
   89b9c:	65f2                	ld	a1,280(sp)
   89b9e:	05e1                	addi	a1,a1,24
   89ba0:	8566                	mv	a0,s9
   89ba2:	865e                	mv	a2,s7
   89ba4:	86da                	mv	a3,s6
   89ba6:	708020ef          	jal	8c2ae <backtrace_release_view>
   89baa:	4d81                	li	s11,0
   89bac:	4881                	li	a7,0
   89bae:	4581                	li	a1,0
   89bb0:	4a81                	li	s5,0
   89bb2:	76013403          	ld	s0,1888(sp)
   89bb6:	58010613          	addi	a2,sp,1408
   89bba:	46010693          	addi	a3,sp,1120
   89bbe:	6a010813          	addi	a6,sp,1696
   89bc2:	a809                	j	89bd4 <elf_add+0xd52>
   89bc4:	98aa                	add	a7,a7,a0
   89bc6:	85be                	mv	a1,a5
   89bc8:	02060613          	addi	a2,a2,32
   89bcc:	02068693          	addi	a3,a3,32
   89bd0:	07060563          	beq	a2,a6,89c3a <elf_add+0xdb8>
   89bd4:	6208                	ld	a0,0(a2)
   89bd6:	c90d                	beqz	a0,89c08 <elf_add+0xd86>
   89bd8:	ff863783          	ld	a5,-8(a2)
   89bdc:	84be                	mv	s1,a5
   89bde:	0157cd63          	blt	a5,s5,89bf8 <elf_add+0xd76>
   89be2:	84d6                	mv	s1,s5
   89be4:	873e                	mv	a4,a5
   89be6:	000a9c63          	bnez	s5,89bfe <elf_add+0xd7c>
   89bea:	97aa                	add	a5,a5,a0
   89bec:	00f5c363          	blt	a1,a5,89bf2 <elf_add+0xd70>
   89bf0:	87ae                	mv	a5,a1
   89bf2:	98aa                	add	a7,a7,a0
   89bf4:	85be                	mv	a1,a5
   89bf6:	a811                	j	89c0a <elf_add+0xd88>
   89bf8:	873e                	mv	a4,a5
   89bfa:	fe0a88e3          	beqz	s5,89bea <elf_add+0xd68>
   89bfe:	8726                	mv	a4,s1
   89c00:	97aa                	add	a5,a5,a0
   89c02:	fef5d7e3          	bge	a1,a5,89bf0 <elf_add+0xd6e>
   89c06:	b7f5                	j	89bf2 <elf_add+0xd70>
   89c08:	8756                	mv	a4,s5
   89c0a:	6288                	ld	a0,0(a3)
   89c0c:	c50d                	beqz	a0,89c36 <elf_add+0xdb4>
   89c0e:	ff86b783          	ld	a5,-8(a3)
   89c12:	84be                	mv	s1,a5
   89c14:	00e7c963          	blt	a5,a4,89c26 <elf_add+0xda4>
   89c18:	84ba                	mv	s1,a4
   89c1a:	8abe                	mv	s5,a5
   89c1c:	e719                	bnez	a4,89c2a <elf_add+0xda8>
   89c1e:	97aa                	add	a5,a5,a0
   89c20:	faf5c2e3          	blt	a1,a5,89bc4 <elf_add+0xd42>
   89c24:	a039                	j	89c32 <elf_add+0xdb0>
   89c26:	8abe                	mv	s5,a5
   89c28:	db7d                	beqz	a4,89c1e <elf_add+0xd9c>
   89c2a:	8aa6                	mv	s5,s1
   89c2c:	97aa                	add	a5,a5,a0
   89c2e:	f8f5cbe3          	blt	a1,a5,89bc4 <elf_add+0xd42>
   89c32:	87ae                	mv	a5,a1
   89c34:	bf41                	j	89bc4 <elf_add+0xd42>
   89c36:	8aba                	mv	s5,a4
   89c38:	bf41                	j	89bc8 <elf_add+0xd46>
   89c3a:	060a8363          	beqz	s5,89ca0 <elf_add+0xe1e>
   89c3e:	c1ad                	beqz	a1,89ca0 <elf_add+0xe1e>
   89c40:	ee22                	sd	s0,280(sp)
   89c42:	415587b3          	sub	a5,a1,s5
   89c46:	20000537          	lui	a0,0x20000
   89c4a:	65c1                	lui	a1,0x10
   89c4c:	00a7a533          	slt	a0,a5,a0
   89c50:	95c6                	add	a1,a1,a7
   89c52:	00b7a5b3          	slt	a1,a5,a1
   89c56:	8d4d                	or	a0,a0,a1
   89c58:	e6da                	sd	s6,328(sp)
   89c5a:	eede                	sd	s7,344(sp)
   89c5c:	eae6                	sd	s9,336(sp)
   89c5e:	fe2a                	sd	a0,312(sp)
   89c60:	14050663          	beqz	a0,89dac <elf_add+0xf2a>
   89c64:	36810e13          	addi	t3,sp,872
   89c68:	8566                	mv	a0,s9
   89c6a:	8cca                	mv	s9,s2
   89c6c:	85ca                	mv	a1,s2
   89c6e:	7632                	ld	a2,296(sp)
   89c70:	76d2                	ld	a3,304(sp)
   89c72:	8756                	mv	a4,s5
   89c74:	885e                	mv	a6,s7
   89c76:	88da                	mv	a7,s6
   89c78:	4f7010ef          	jal	8b96e <elf_get_view>
   89c7c:	1a050863          	beqz	a0,89e2c <elf_add+0xfaa>
   89c80:	4505                	li	a0,1
   89c82:	fa2a                	sd	a0,304(sp)
   89c84:	a2dd                	j	89e6a <elf_add+0xfe8>
   89c86:	85aa                	mv	a1,a0
   89c88:	6108                	ld	a0,0(a0)
   89c8a:	fd75                	bnez	a0,89c86 <elf_add+0xe04>
   89c8c:	e180                	sd	s0,0(a1)
   89c8e:	8b4a                	mv	s6,s2
   89c90:	6bf6                	ld	s7,344(sp)
   89c92:	6916                	ld	s2,320(sp)
   89c94:	8cea                	mv	s9,s10
   89c96:	6a4e                	ld	s4,208(sp)
   89c98:	6aa6                	ld	s5,72(sp)
   89c9a:	7d2e                	ld	s10,232(sp)
   89c9c:	f70ff06f          	j	8940c <elf_add+0x58a>
   89ca0:	1a094263          	bltz	s2,89e44 <elf_add+0xfc2>
   89ca4:	854a                	mv	a0,s2
   89ca6:	85de                	mv	a1,s7
   89ca8:	865a                	mv	a2,s6
   89caa:	dcdfb0ef          	jal	85a76 <backtrace_close>
   89cae:	85aa                	mv	a1,a0
   89cb0:	4505                	li	a0,1
   89cb2:	f0059063          	bnez	a1,893b2 <elf_add+0x530>
   89cb6:	4981                	li	s3,0
   89cb8:	dfaff06f          	j	892b2 <elf_add+0x430>
   89cbc:	00061517          	auipc	a0,0x61
   89cc0:	9de50593          	addi	a1,a0,-1570 # ea69a <_ZZL13pch_open_fileP10cpp_readerP9_cpp_filePbE9extension+0x227f>
   89cc4:	855a                	mv	a0,s6
   89cc6:	4601                	li	a2,0
   89cc8:	9b82                	jalr	s7
   89cca:	4a85                	li	s5,1
   89ccc:	4485                	li	s1,1
   89cce:	6d012503          	lw	a0,1744(sp)
   89cd2:	c901                	beqz	a0,89ce2 <elf_add+0xe60>
   89cd4:	6b810593          	addi	a1,sp,1720
   89cd8:	8566                	mv	a0,s9
   89cda:	865e                	mv	a2,s7
   89cdc:	86da                	mv	a3,s6
   89cde:	5d0020ef          	jal	8c2ae <backtrace_release_view>
   89ce2:	6b012503          	lw	a0,1712(sp)
   89ce6:	c901                	beqz	a0,89cf6 <elf_add+0xe74>
   89ce8:	69810593          	addi	a1,sp,1688
   89cec:	8566                	mv	a0,s9
   89cee:	865e                	mv	a2,s7
   89cf0:	86da                	mv	a3,s6
   89cf2:	5bc020ef          	jal	8c2ae <backtrace_release_view>
   89cf6:	45012503          	lw	a0,1104(sp)
   89cfa:	00153513          	seqz	a0,a0
   89cfe:	8d45                	or	a0,a0,s1
   89d00:	e901                	bnez	a0,89d10 <elf_add+0xe8e>
   89d02:	43810593          	addi	a1,sp,1080
   89d06:	8566                	mv	a0,s9
   89d08:	865e                	mv	a2,s7
   89d0a:	86da                	mv	a3,s6
   89d0c:	5a2020ef          	jal	8c2ae <backtrace_release_view>
   89d10:	43012503          	lw	a0,1072(sp)
   89d14:	00153513          	seqz	a0,a0
   89d18:	00aae533          	or	a0,s5,a0
   89d1c:	6ace                	ld	s5,208(sp)
   89d1e:	e901                	bnez	a0,89d2e <elf_add+0xeac>
   89d20:	41810593          	addi	a1,sp,1048
   89d24:	8566                	mv	a0,s9
   89d26:	865e                	mv	a2,s7
   89d28:	86da                	mv	a3,s6
   89d2a:	584020ef          	jal	8c2ae <backtrace_release_view>
   89d2e:	7572                	ld	a0,312(sp)
   89d30:	c911                	beqz	a0,89d44 <elf_add+0xec2>
   89d32:	3f012503          	lw	a0,1008(sp)
   89d36:	c519                	beqz	a0,89d44 <elf_add+0xec2>
   89d38:	0fac                	addi	a1,sp,984
   89d3a:	8566                	mv	a0,s9
   89d3c:	865e                	mv	a2,s7
   89d3e:	86da                	mv	a3,s6
   89d40:	56e020ef          	jal	8c2ae <backtrace_release_view>
   89d44:	000c0b63          	beqz	s8,89d5a <elf_add+0xed8>
   89d48:	3d012503          	lw	a0,976(sp)
   89d4c:	c519                	beqz	a0,89d5a <elf_add+0xed8>
   89d4e:	1f2c                	addi	a1,sp,952
   89d50:	8566                	mv	a0,s9
   89d52:	865e                	mv	a2,s7
   89d54:	86da                	mv	a3,s6
   89d56:	558020ef          	jal	8c2ae <backtrace_release_view>
   89d5a:	000a8b63          	beqz	s5,89d70 <elf_add+0xeee>
   89d5e:	3b012503          	lw	a0,944(sp)
   89d62:	c519                	beqz	a0,89d70 <elf_add+0xeee>
   89d64:	0f2c                	addi	a1,sp,920
   89d66:	8566                	mv	a0,s9
   89d68:	865e                	mv	a2,s7
   89d6a:	86da                	mv	a3,s6
   89d6c:	542020ef          	jal	8c2ae <backtrace_release_view>
   89d70:	754a                	ld	a0,176(sp)
   89d72:	d4050063          	beqz	a0,892b2 <elf_add+0x430>
   89d76:	41012503          	lw	a0,1040(sp)
   89d7a:	d2050c63          	beqz	a0,892b2 <elf_add+0x430>
   89d7e:	1fac                	addi	a1,sp,1016
   89d80:	8566                	mv	a0,s9
   89d82:	865e                	mv	a2,s7
   89d84:	86da                	mv	a3,s6
   89d86:	528020ef          	jal	8c2ae <backtrace_release_view>
   89d8a:	d28ff06f          	j	892b2 <elf_add+0x430>
   89d8e:	fe56                	sd	s5,312(sp)
   89d90:	6d8a                	ld	s11,128(sp)
   89d92:	7c6a                	ld	s8,184(sp)
   89d94:	f902                	sd	zero,176(sp)
   89d96:	bf15                	j	89cca <elf_add+0xe48>
   89d98:	6d8a                	ld	s11,128(sp)
   89d9a:	7c6a                	ld	s8,184(sp)
   89d9c:	e9d2                	sd	s4,208(sp)
   89d9e:	fe02                	sd	zero,312(sp)
   89da0:	b72d                	j	89cca <elf_add+0xe48>
   89da2:	fe56                	sd	s5,312(sp)
   89da4:	6d8a                	ld	s11,128(sp)
   89da6:	7c6a                	ld	s8,184(sp)
   89da8:	e982                	sd	zero,208(sp)
   89daa:	b705                	j	89cca <elf_add+0xe48>
   89dac:	7c32                	ld	s8,296(sp)
   89dae:	7a52                	ld	s4,304(sp)
   89db0:	8cca                	mv	s9,s2
   89db2:	04a8                	addi	a0,sp,584
   89db4:	12000613          	li	a2,288
   89db8:	4581                	li	a1,0
   89dba:	f568a0ef          	jal	14510 <memset@plt>
   89dbe:	4401                	li	s0,0
   89dc0:	4b01                	li	s6,0
   89dc2:	23810993          	addi	s3,sp,568
   89dc6:	57810b93          	addi	s7,sp,1400
   89dca:	45810913          	addi	s2,sp,1112
   89dce:	a821                	j	89de6 <elf_add+0xf64>
   89dd0:	008905b3          	add	a1,s2,s0
   89dd4:	e988                	sd	a0,16(a1)
   89dd6:	0b05                	addi	s6,s6,1
   89dd8:	02040413          	addi	s0,s0,32
   89ddc:	0985                	addi	s3,s3,1
   89dde:	12000513          	li	a0,288
   89de2:	08a40363          	beq	s0,a0,89e68 <elf_add+0xfe6>
   89de6:	008b8533          	add	a0,s7,s0
   89dea:	6504                	ld	s1,8(a0)
   89dec:	87a6                	mv	a5,s1
   89dee:	e881                	bnez	s1,89dfe <elf_add+0xf7c>
   89df0:	00890533          	add	a0,s2,s0
   89df4:	651c                	ld	a5,8(a0)
   89df6:	d3e5                	beqz	a5,89dd6 <elf_add+0xf54>
   89df8:	005b1513          	slli	a0,s6,0x5
   89dfc:	954a                	add	a0,a0,s2
   89dfe:	6118                	ld	a4,0(a0)
   89e00:	24810d13          	addi	s10,sp,584
   89e04:	9d22                	add	s10,s10,s0
   89e06:	6556                	ld	a0,336(sp)
   89e08:	85e6                	mv	a1,s9
   89e0a:	8662                	mv	a2,s8
   89e0c:	86d2                	mv	a3,s4
   89e0e:	6876                	ld	a6,344(sp)
   89e10:	68b6                	ld	a7,328(sp)
   89e12:	8e6a                	mv	t3,s10
   89e14:	35b010ef          	jal	8b96e <elf_get_view>
   89e18:	c911                	beqz	a0,89e2c <elf_add+0xfaa>
   89e1a:	000d3503          	ld	a0,0(s10)
   89e1e:	4585                	li	a1,1
   89e20:	00b98023          	sb	a1,0(s3)
   89e24:	d4d5                	beqz	s1,89dd0 <elf_add+0xf4e>
   89e26:	008b85b3          	add	a1,s7,s0
   89e2a:	b76d                	j	89dd4 <elf_add+0xf52>
   89e2c:	4981                	li	s3,0
   89e2e:	6b36                	ld	s6,328(sp)
   89e30:	6bf6                	ld	s7,344(sp)
   89e32:	8966                	mv	s2,s9
   89e34:	6cd6                	ld	s9,336(sp)
   89e36:	c7cff06f          	j	892b2 <elf_add+0x430>
   89e3a:	fe56                	sd	s5,312(sp)
   89e3c:	6d8a                	ld	s11,128(sp)
   89e3e:	e9d2                	sd	s4,208(sp)
   89e40:	4c01                	li	s8,0
   89e42:	b561                	j	89cca <elf_add+0xe48>
   89e44:	4505                	li	a0,1
   89e46:	d6cff06f          	j	893b2 <elf_add+0x530>
   89e4a:	fe56                	sd	s5,312(sp)
   89e4c:	6d8a                	ld	s11,128(sp)
   89e4e:	7c6a                	ld	s8,184(sp)
   89e50:	4505                	li	a0,1
   89e52:	f92a                	sd	a0,176(sp)
   89e54:	bd9d                	j	89cca <elf_add+0xe48>
   89e56:	fe56                	sd	s5,312(sp)
   89e58:	6d8a                	ld	s11,128(sp)
   89e5a:	7c6a                	ld	s8,184(sp)
   89e5c:	b5bd                	j	89cca <elf_add+0xe48>
   89e5e:	fe56                	sd	s5,312(sp)
   89e60:	6d8a                	ld	s11,128(sp)
   89e62:	7c6a                	ld	s8,184(sp)
   89e64:	e9d2                	sd	s4,208(sp)
   89e66:	b595                	j	89cca <elf_add+0xe48>
   89e68:	fa02                	sd	zero,304(sp)
   89e6a:	e2e6                	sd	s9,320(sp)
   89e6c:	000ccb63          	bltz	s9,89e82 <elf_add+0x1000>
   89e70:	8566                	mv	a0,s9
   89e72:	65f6                	ld	a1,344(sp)
   89e74:	6636                	ld	a2,328(sp)
   89e76:	c01fb0ef          	jal	85a76 <backtrace_close>
   89e7a:	4a050863          	beqz	a0,8a32a <elf_add+0x14a8>
   89e7e:	557d                	li	a0,-1
   89e80:	e2aa                	sd	a0,320(sp)
   89e82:	7572                	ld	a0,312(sp)
   89e84:	28050f63          	beqz	a0,8a122 <elf_add+0x12a0>
   89e88:	57813883          	ld	a7,1400(sp)
   89e8c:	58013503          	ld	a0,1408(sp)
   89e90:	f9aa                	sd	a0,240(sp)
   89e92:	59813803          	ld	a6,1432(sp)
   89e96:	5a013503          	ld	a0,1440(sp)
   89e9a:	edaa                	sd	a0,216(sp)
   89e9c:	45813283          	ld	t0,1112(sp)
   89ea0:	46013503          	ld	a0,1120(sp)
   89ea4:	f62a                	sd	a0,296(sp)
   89ea6:	47813303          	ld	t1,1144(sp)
   89eaa:	48013503          	ld	a0,1152(sp)
   89eae:	e22a                	sd	a0,256(sp)
   89eb0:	5b813383          	ld	t2,1464(sp)
   89eb4:	5c013e83          	ld	t4,1472(sp)
   89eb8:	5d813483          	ld	s1,1496(sp)
   89ebc:	5e013503          	ld	a0,1504(sp)
   89ec0:	e1aa                	sd	a0,192(sp)
   89ec2:	49813503          	ld	a0,1176(sp)
   89ec6:	4a013583          	ld	a1,1184(sp)
   89eca:	f5ae                	sd	a1,232(sp)
   89ecc:	4b813583          	ld	a1,1208(sp)
   89ed0:	4c013603          	ld	a2,1216(sp)
   89ed4:	f1b2                	sd	a2,224(sp)
   89ed6:	5f813703          	ld	a4,1528(sp)
   89eda:	60013e03          	ld	t3,1536(sp)
   89ede:	61813783          	ld	a5,1560(sp)
   89ee2:	62013603          	ld	a2,1568(sp)
   89ee6:	f132                	sd	a2,160(sp)
   89ee8:	4d813603          	ld	a2,1240(sp)
   89eec:	4e013683          	ld	a3,1248(sp)
   89ef0:	e9b6                	sd	a3,208(sp)
   89ef2:	4f813683          	ld	a3,1272(sp)
   89ef6:	50013403          	ld	s0,1280(sp)
   89efa:	e5a2                	sd	s0,200(sp)
   89efc:	41588cb3          	sub	s9,a7,s5
   89f00:	41528c33          	sub	s8,t0,s5
   89f04:	41580433          	sub	s0,a6,s5
   89f08:	e922                	sd	s0,144(sp)
   89f0a:	415309b3          	sub	s3,t1,s5
   89f0e:	41538b33          	sub	s6,t2,s5
   89f12:	41550d33          	sub	s10,a0,s5
   89f16:	415480b3          	sub	ra,s1,s5
   89f1a:	41558f33          	sub	t5,a1,s5
   89f1e:	41570fb3          	sub	t6,a4,s5
   89f22:	41560933          	sub	s2,a2,s5
   89f26:	41578a33          	sub	s4,a5,s5
   89f2a:	41568bb3          	sub	s7,a3,s5
   89f2e:	63813503          	ld	a0,1592(sp)
   89f32:	64013583          	ld	a1,1600(sp)
   89f36:	fd2e                	sd	a1,184(sp)
   89f38:	65813683          	ld	a3,1624(sp)
   89f3c:	66013303          	ld	t1,1632(sp)
   89f40:	fc9a                	sd	t1,120(sp)
   89f42:	41550533          	sub	a0,a0,s5
   89f46:	f4aa                	sd	a0,104(sp)
   89f48:	51813503          	ld	a0,1304(sp)
   89f4c:	52013583          	ld	a1,1312(sp)
   89f50:	f92e                	sd	a1,176(sp)
   89f52:	53813703          	ld	a4,1336(sp)
   89f56:	54013583          	ld	a1,1344(sp)
   89f5a:	f52e                	sd	a1,168(sp)
   89f5c:	41550533          	sub	a0,a0,s5
   89f60:	f0aa                	sd	a0,96(sp)
   89f62:	41568533          	sub	a0,a3,s5
   89f66:	ecaa                	sd	a0,88(sp)
   89f68:	67813683          	ld	a3,1656(sp)
   89f6c:	415703b3          	sub	t2,a4,s5
   89f70:	55813703          	ld	a4,1368(sp)
   89f74:	68013583          	ld	a1,1664(sp)
   89f78:	e12e                	sd	a1,128(sp)
   89f7a:	415682b3          	sub	t0,a3,s5
   89f7e:	56013503          	ld	a0,1376(sp)
   89f82:	e52a                	sd	a0,136(sp)
   89f84:	415708b3          	sub	a7,a4,s5
   89f88:	74ce                	ld	s1,240(sp)
   89f8a:	00903733          	snez	a4,s1
   89f8e:	666e                	ld	a2,216(sp)
   89f90:	00c03433          	snez	s0,a2
   89f94:	9722                	add	a4,a4,s0
   89f96:	e8ba                	sd	a4,80(sp)
   89f98:	01d03733          	snez	a4,t4
   89f9c:	680e                	ld	a6,192(sp)
   89f9e:	010036b3          	snez	a3,a6
   89fa2:	00d70433          	add	s0,a4,a3
   89fa6:	01c03ab3          	snez	s5,t3
   89faa:	768a                	ld	a3,160(sp)
   89fac:	00d03733          	snez	a4,a3
   89fb0:	9756                	add	a4,a4,s5
   89fb2:	f8ba                	sd	a4,112(sp)
   89fb4:	36813783          	ld	a5,872(sp)
   89fb8:	00603533          	snez	a0,t1
   89fbc:	00b03ab3          	snez	s5,a1
   89fc0:	9556                	add	a0,a0,s5
   89fc2:	ed2a                	sd	a0,152(sp)
   89fc4:	9cbe                	add	s9,s9,a5
   89fc6:	9c3e                	add	s8,s8,a5
   89fc8:	654a                	ld	a0,144(sp)
   89fca:	953e                	add	a0,a0,a5
   89fcc:	99be                	add	s3,s3,a5
   89fce:	9b3e                	add	s6,s6,a5
   89fd0:	9d3e                	add	s10,s10,a5
   89fd2:	90be                	add	ra,ra,a5
   89fd4:	9f3e                	add	t5,t5,a5
   89fd6:	9fbe                	add	t6,t6,a5
   89fd8:	993e                	add	s2,s2,a5
   89fda:	9a3e                	add	s4,s4,a5
   89fdc:	9bbe                	add	s7,s7,a5
   89fde:	7326                	ld	t1,104(sp)
   89fe0:	933e                	add	t1,t1,a5
   89fe2:	7a86                	ld	s5,96(sp)
   89fe4:	9abe                	add	s5,s5,a5
   89fe6:	65e6                	ld	a1,88(sp)
   89fe8:	95be                	add	a1,a1,a5
   89fea:	f0ae                	sd	a1,96(sp)
   89fec:	93be                	add	t2,t2,a5
   89fee:	f49e                	sd	t2,104(sp)
   89ff0:	92be                	add	t0,t0,a5
   89ff2:	e916                	sd	t0,144(sp)
   89ff4:	011783b3          	add	t2,a5,a7
   89ff8:	0014b593          	seqz	a1,s1
   89ffc:	15fd                	addi	a1,a1,-1 # ffff <_PROCEDURE_LINKAGE_TABLE_-0x3d51>
   89ffe:	0195fcb3          	and	s9,a1,s9
   8a002:	75b2                	ld	a1,296(sp)
   8a004:	0015b713          	seqz	a4,a1
   8a008:	177d                	addi	a4,a4,-1
   8a00a:	01877c33          	and	s8,a4,s8
   8a00e:	00163793          	seqz	a5,a2
   8a012:	17fd                	addi	a5,a5,-1
   8a014:	00a7f8b3          	and	a7,a5,a0
   8a018:	6512                	ld	a0,256(sp)
   8a01a:	00153793          	seqz	a5,a0
   8a01e:	17fd                	addi	a5,a5,-1
   8a020:	0137f9b3          	and	s3,a5,s3
   8a024:	001eb713          	seqz	a4,t4
   8a028:	177d                	addi	a4,a4,-1
   8a02a:	016772b3          	and	t0,a4,s6
   8a02e:	752e                	ld	a0,232(sp)
   8a030:	00153593          	seqz	a1,a0
   8a034:	15fd                	addi	a1,a1,-1
   8a036:	01a5fb33          	and	s6,a1,s10
   8a03a:	00183613          	seqz	a2,a6
   8a03e:	167d                	addi	a2,a2,-1
   8a040:	001670b3          	and	ra,a2,ra
   8a044:	6d46                	ld	s10,80(sp)
   8a046:	9d22                	add	s10,s10,s0
   8a048:	750e                	ld	a0,224(sp)
   8a04a:	00153413          	seqz	s0,a0
   8a04e:	147d                	addi	s0,s0,-1
   8a050:	01e47833          	and	a6,s0,t5
   8a054:	001e3793          	seqz	a5,t3
   8a058:	17fd                	addi	a5,a5,-1
   8a05a:	01f7ffb3          	and	t6,a5,t6
   8a05e:	654e                	ld	a0,208(sp)
   8a060:	00153513          	seqz	a0,a0
   8a064:	157d                	addi	a0,a0,-1
   8a066:	01257f33          	and	t5,a0,s2
   8a06a:	0016b593          	seqz	a1,a3
   8a06e:	15fd                	addi	a1,a1,-1
   8a070:	0145f5b3          	and	a1,a1,s4
   8a074:	652e                	ld	a0,200(sp)
   8a076:	00153713          	seqz	a4,a0
   8a07a:	177d                	addi	a4,a4,-1
   8a07c:	01777933          	and	s2,a4,s7
   8a080:	756a                	ld	a0,184(sp)
   8a082:	00153493          	seqz	s1,a0
   8a086:	14fd                	addi	s1,s1,-1
   8a088:	0064f4b3          	and	s1,s1,t1
   8a08c:	00a036b3          	snez	a3,a0
   8a090:	7546                	ld	a0,112(sp)
   8a092:	96aa                	add	a3,a3,a0
   8a094:	754a                	ld	a0,176(sp)
   8a096:	00153513          	seqz	a0,a0
   8a09a:	157d                	addi	a0,a0,-1
   8a09c:	01557533          	and	a0,a0,s5
   8a0a0:	7666                	ld	a2,120(sp)
   8a0a2:	00163613          	seqz	a2,a2
   8a0a6:	167d                	addi	a2,a2,-1
   8a0a8:	7706                	ld	a4,96(sp)
   8a0aa:	8e79                	and	a2,a2,a4
   8a0ac:	772a                	ld	a4,168(sp)
   8a0ae:	00173413          	seqz	s0,a4
   8a0b2:	147d                	addi	s0,s0,-1
   8a0b4:	7726                	ld	a4,104(sp)
   8a0b6:	8c79                	and	s0,s0,a4
   8a0b8:	670a                	ld	a4,128(sp)
   8a0ba:	00173793          	seqz	a5,a4
   8a0be:	17fd                	addi	a5,a5,-1
   8a0c0:	674a                	ld	a4,144(sp)
   8a0c2:	8ff9                	and	a5,a5,a4
   8a0c4:	672a                	ld	a4,136(sp)
   8a0c6:	00173713          	seqz	a4,a4
   8a0ca:	177d                	addi	a4,a4,-1
   8a0cc:	00777733          	and	a4,a4,t2
   8a0d0:	59913423          	sd	s9,1416(sp)
   8a0d4:	5b113423          	sd	a7,1448(sp)
   8a0d8:	5c513423          	sd	t0,1480(sp)
   8a0dc:	5e113423          	sd	ra,1512(sp)
   8a0e0:	47813423          	sd	s8,1128(sp)
   8a0e4:	49313423          	sd	s3,1160(sp)
   8a0e8:	4b613423          	sd	s6,1192(sp)
   8a0ec:	4d013423          	sd	a6,1224(sp)
   8a0f0:	96ea                	add	a3,a3,s10
   8a0f2:	61f13423          	sd	t6,1544(sp)
   8a0f6:	62b13423          	sd	a1,1576(sp)
   8a0fa:	64913423          	sd	s1,1608(sp)
   8a0fe:	66c13423          	sd	a2,1640(sp)
   8a102:	4fe13423          	sd	t5,1256(sp)
   8a106:	51213423          	sd	s2,1288(sp)
   8a10a:	52a13423          	sd	a0,1320(sp)
   8a10e:	54813423          	sd	s0,1352(sp)
   8a112:	68f13423          	sd	a5,1672(sp)
   8a116:	656a                	ld	a0,152(sp)
   8a118:	9d35                	addw	a0,a0,a3
   8a11a:	f62a                	sd	a0,296(sp)
   8a11c:	56e13423          	sd	a4,1384(sp)
   8a120:	a011                	j	8a124 <elf_add+0x12a2>
   8a122:	f602                	sd	zero,296(sp)
   8a124:	4a01                	li	s4,0
   8a126:	4a81                	li	s5,0
   8a128:	23810b13          	addi	s6,sp,568
   8a12c:	57810d13          	addi	s10,sp,1400
   8a130:	45810993          	addi	s3,sp,1112
   8a134:	6505                	lui	a0,0x1
   8a136:	3b450b93          	addi	s7,a0,948 # 13b4 <_PROCEDURE_LINKAGE_TABLE_-0x1299c>
   8a13a:	12000913          	li	s2,288
   8a13e:	6cb6                	ld	s9,328(sp)
   8a140:	a801                	j	8a150 <elf_add+0x12ce>
   8a142:	000b0023          	sb	zero,0(s6)
   8a146:	020a0a13          	addi	s4,s4,32
   8a14a:	0b05                	addi	s6,s6,1
   8a14c:	072a0863          	beq	s4,s2,8a1bc <elf_add+0x133a>
   8a150:	014d04b3          	add	s1,s10,s4
   8a154:	6488                	ld	a0,8(s1)
   8a156:	f965                	bnez	a0,8a146 <elf_add+0x12c4>
   8a158:	01498433          	add	s0,s3,s4
   8a15c:	00843c03          	ld	s8,8(s0)
   8a160:	fe0c03e3          	beqz	s8,8a146 <elf_add+0x12c4>
   8a164:	000a9b63          	bnez	s5,8a17a <elf_add+0x12f8>
   8a168:	6556                	ld	a0,336(sp)
   8a16a:	85de                	mv	a1,s7
   8a16c:	6676                	ld	a2,344(sp)
   8a16e:	86e6                	mv	a3,s9
   8a170:	ba4fb0ef          	jal	85514 <backtrace_alloc>
   8a174:	8aaa                	mv	s5,a0
   8a176:	1a050a63          	beqz	a0,8a32a <elf_add+0x14a8>
   8a17a:	680c                	ld	a1,16(s0)
   8a17c:	17010813          	addi	a6,sp,368
   8a180:	16010893          	addi	a7,sp,352
   8a184:	6556                	ld	a0,336(sp)
   8a186:	8662                	mv	a2,s8
   8a188:	86d6                	mv	a3,s5
   8a18a:	6776                	ld	a4,344(sp)
   8a18c:	87e6                	mv	a5,s9
   8a18e:	98bfb0ef          	jal	85b18 <elf_uncompress_zdebug>
   8a192:	18050c63          	beqz	a0,8a32a <elf_add+0x14a8>
   8a196:	7516                	ld	a0,352(sp)
   8a198:	75d6                	ld	a1,368(sp)
   8a19a:	000b4603          	lbu	a2,0(s6)
   8a19e:	e488                	sd	a0,8(s1)
   8a1a0:	e88c                	sd	a1,16(s1)
   8a1a2:	0004ac23          	sw	zero,24(s1)
   8a1a6:	d245                	beqz	a2,8a146 <elf_add+0x12c4>
   8a1a8:	04ac                	addi	a1,sp,584
   8a1aa:	95d2                	add	a1,a1,s4
   8a1ac:	4d88                	lw	a0,24(a1)
   8a1ae:	d951                	beqz	a0,8a142 <elf_add+0x12c0>
   8a1b0:	6556                	ld	a0,336(sp)
   8a1b2:	6676                	ld	a2,344(sp)
   8a1b4:	86e6                	mv	a3,s9
   8a1b6:	0f8020ef          	jal	8c2ae <backtrace_release_view>
   8a1ba:	b761                	j	8a142 <elf_add+0x12c0>
   8a1bc:	000a8b63          	beqz	s5,8a1d2 <elf_add+0x1350>
   8a1c0:	6505                	lui	a0,0x1
   8a1c2:	3b450613          	addi	a2,a0,948 # 13b4 <_PROCEDURE_LINKAGE_TABLE_-0x1299c>
   8a1c6:	6556                	ld	a0,336(sp)
   8a1c8:	85d6                	mv	a1,s5
   8a1ca:	66f6                	ld	a3,344(sp)
   8a1cc:	8766                	mv	a4,s9
   8a1ce:	c68fb0ef          	jal	85636 <backtrace_free>
   8a1d2:	4a01                	li	s4,0
   8a1d4:	4a81                	li	s5,0
   8a1d6:	23810c13          	addi	s8,sp,568
   8a1da:	57810d13          	addi	s10,sp,1400
   8a1de:	12000b13          	li	s6,288
   8a1e2:	24810993          	addi	s3,sp,584
   8a1e6:	74f2                	ld	s1,312(sp)
   8a1e8:	7932                	ld	s2,296(sp)
   8a1ea:	a039                	j	8a1f8 <elf_add+0x1376>
   8a1ec:	397d                	addiw	s2,s2,-1
   8a1ee:	020a0a13          	addi	s4,s4,32
   8a1f2:	0c05                	addi	s8,s8,1
   8a1f4:	076a0963          	beq	s4,s6,8a266 <elf_add+0x13e4>
   8a1f8:	014d0433          	add	s0,s10,s4
   8a1fc:	00843b83          	ld	s7,8(s0)
   8a200:	fe0b87e3          	beqz	s7,8a1ee <elf_add+0x136c>
   8a204:	4c08                	lw	a0,24(s0)
   8a206:	d565                	beqz	a0,8a1ee <elf_add+0x136c>
   8a208:	000a9b63          	bnez	s5,8a21e <elf_add+0x139c>
   8a20c:	6591                	lui	a1,0x4
   8a20e:	6556                	ld	a0,336(sp)
   8a210:	6676                	ld	a2,344(sp)
   8a212:	86e6                	mv	a3,s9
   8a214:	b00fb0ef          	jal	85514 <backtrace_alloc>
   8a218:	8aaa                	mv	s5,a0
   8a21a:	10050863          	beqz	a0,8a32a <elf_add+0x14a8>
   8a21e:	680c                	ld	a1,16(s0)
   8a220:	17010813          	addi	a6,sp,368
   8a224:	16010893          	addi	a7,sp,352
   8a228:	6556                	ld	a0,336(sp)
   8a22a:	865e                	mv	a2,s7
   8a22c:	86d6                	mv	a3,s5
   8a22e:	6776                	ld	a4,344(sp)
   8a230:	87e6                	mv	a5,s9
   8a232:	6b7010ef          	jal	8c0e8 <elf_uncompress_chdr>
   8a236:	0e050a63          	beqz	a0,8a32a <elf_add+0x14a8>
   8a23a:	7516                	ld	a0,352(sp)
   8a23c:	75d6                	ld	a1,368(sp)
   8a23e:	e408                	sd	a0,8(s0)
   8a240:	e80c                	sd	a1,16(s0)
   8a242:	00042c23          	sw	zero,24(s0)
   8a246:	f0dd                	bnez	s1,8a1ec <elf_add+0x136a>
   8a248:	000c4503          	lbu	a0,0(s8)
   8a24c:	d14d                	beqz	a0,8a1ee <elf_add+0x136c>
   8a24e:	014985b3          	add	a1,s3,s4
   8a252:	4d88                	lw	a0,24(a1)
   8a254:	c511                	beqz	a0,8a260 <elf_add+0x13de>
   8a256:	6556                	ld	a0,336(sp)
   8a258:	6676                	ld	a2,344(sp)
   8a25a:	86e6                	mv	a3,s9
   8a25c:	052020ef          	jal	8c2ae <backtrace_release_view>
   8a260:	000c0023          	sb	zero,0(s8)
   8a264:	b769                	j	8a1ee <elf_add+0x136c>
   8a266:	000a8963          	beqz	s5,8a278 <elf_add+0x13f6>
   8a26a:	6611                	lui	a2,0x4
   8a26c:	6556                	ld	a0,336(sp)
   8a26e:	85d6                	mv	a1,s5
   8a270:	66f6                	ld	a3,344(sp)
   8a272:	6736                	ld	a4,328(sp)
   8a274:	bc2fb0ef          	jal	85636 <backtrace_free>
   8a278:	00193513          	seqz	a0,s2
   8a27c:	8d65                	and	a0,a0,s1
   8a27e:	c919                	beqz	a0,8a294 <elf_add+0x1412>
   8a280:	38012503          	lw	a0,896(sp)
   8a284:	c519                	beqz	a0,8a292 <elf_add+0x1410>
   8a286:	16ac                	addi	a1,sp,872
   8a288:	6556                	ld	a0,336(sp)
   8a28a:	6676                	ld	a2,344(sp)
   8a28c:	66b6                	ld	a3,328(sp)
   8a28e:	020020ef          	jal	8c2ae <backtrace_release_view>
   8a292:	fa02                	sd	zero,304(sp)
   8a294:	58013503          	ld	a0,1408(sp)
   8a298:	58813803          	ld	a6,1416(sp)
   8a29c:	5a013603          	ld	a2,1440(sp)
   8a2a0:	5a813883          	ld	a7,1448(sp)
   8a2a4:	68013283          	ld	t0,1664(sp)
   8a2a8:	68813703          	ld	a4,1672(sp)
   8a2ac:	5c013483          	ld	s1,1472(sp)
   8a2b0:	5c813403          	ld	s0,1480(sp)
   8a2b4:	5e013303          	ld	t1,1504(sp)
   8a2b8:	5e813683          	ld	a3,1512(sp)
   8a2bc:	fb3a                	sd	a4,432(sp)
   8a2be:	ff2a                	sd	a0,440(sp)
   8a2c0:	e3b2                	sd	a2,448(sp)
   8a2c2:	e7a6                	sd	s1,456(sp)
   8a2c4:	60013503          	ld	a0,1536(sp)
   8a2c8:	60813603          	ld	a2,1544(sp)
   8a2cc:	62013703          	ld	a4,1568(sp)
   8a2d0:	62813483          	ld	s1,1576(sp)
   8a2d4:	fac2                	sd	a6,368(sp)
   8a2d6:	fec6                	sd	a7,376(sp)
   8a2d8:	e322                	sd	s0,384(sp)
   8a2da:	e736                	sd	a3,392(sp)
   8a2dc:	64013683          	ld	a3,1600(sp)
   8a2e0:	64813403          	ld	s0,1608(sp)
   8a2e4:	66013783          	ld	a5,1632(sp)
   8a2e8:	66813583          	ld	a1,1640(sp)
   8a2ec:	eb9a                	sd	t1,464(sp)
   8a2ee:	efaa                	sd	a0,472(sp)
   8a2f0:	f3ba                	sd	a4,480(sp)
   8a2f2:	f7b6                	sd	a3,488(sp)
   8a2f4:	eb32                	sd	a2,400(sp)
   8a2f6:	ef26                	sd	s1,408(sp)
   8a2f8:	f322                	sd	s0,416(sp)
   8a2fa:	f72e                	sd	a1,424(sp)
   8a2fc:	7736                	ld	a4,360(sp)
   8a2fe:	fbbe                	sd	a5,496(sp)
   8a300:	ff96                	sd	t0,504(sp)
   8a302:	7512                	ld	a0,288(sp)
   8a304:	1579                	addi	a0,a0,-2
   8a306:	00153693          	seqz	a3,a0
   8a30a:	1a90                	addi	a2,sp,368
   8a30c:	6572                	ld	a0,280(sp)
   8a30e:	e02a                	sd	a0,0(sp)
   8a310:	6556                	ld	a0,336(sp)
   8a312:	65d2                	ld	a1,272(sp)
   8a314:	67f6                	ld	a5,344(sp)
   8a316:	6836                	ld	a6,328(sp)
   8a318:	68b2                	ld	a7,264(sp)
   8a31a:	7cd010ef          	jal	8c2e6 <backtrace_dwarf_add>
   8a31e:	c511                	beqz	a0,8a32a <elf_add+0x14a8>
   8a320:	4505                	li	a0,1
   8a322:	75ee                	ld	a1,248(sp)
   8a324:	c188                	sw	a0,0(a1)
   8a326:	88cff06f          	j	893b2 <elf_add+0x530>
   8a32a:	4981                	li	s3,0
   8a32c:	7552                	ld	a0,304(sp)
   8a32e:	c10d                	beqz	a0,8a350 <elf_add+0x14ce>
   8a330:	38012503          	lw	a0,896(sp)
   8a334:	cd11                	beqz	a0,8a350 <elf_add+0x14ce>
   8a336:	16ac                	addi	a1,sp,872
   8a338:	6cd6                	ld	s9,336(sp)
   8a33a:	8566                	mv	a0,s9
   8a33c:	6bf6                	ld	s7,344(sp)
   8a33e:	865e                	mv	a2,s7
   8a340:	6b36                	ld	s6,328(sp)
   8a342:	86da                	mv	a3,s6
   8a344:	76b010ef          	jal	8c2ae <backtrace_release_view>
   8a348:	4981                	li	s3,0
   8a34a:	6916                	ld	s2,320(sp)
   8a34c:	f67fe06f          	j	892b2 <elf_add+0x430>
   8a350:	6b36                	ld	s6,328(sp)
   8a352:	6bf6                	ld	s7,344(sp)
   8a354:	d4bfe06f          	j	8909e <elf_add+0x21c>
   8a358:	4a81                	li	s5,0
   8a35a:	4481                	li	s1,0
   8a35c:	8b4a                	mv	s6,s2
   8a35e:	6bf6                	ld	s7,344(sp)
   8a360:	6916                	ld	s2,320(sp)
   8a362:	8cea                	mv	s9,s10
   8a364:	b2ad                	j	89cce <elf_add+0xe4c>
   8a366:	4661                	li	a2,24
   8a368:	8cea                	mv	s9,s10
   8a36a:	856a                	mv	a0,s10
   8a36c:	85a2                	mv	a1,s0
   8a36e:	6bf6                	ld	s7,344(sp)
   8a370:	86de                	mv	a3,s7
   8a372:	8b4a                	mv	s6,s2
   8a374:	874a                	mv	a4,s2
   8a376:	ac0fb0ef          	jal	85636 <backtrace_free>
   8a37a:	4a81                	li	s5,0
   8a37c:	4481                	li	s1,0
   8a37e:	6916                	ld	s2,320(sp)
   8a380:	b2b9                	j	89cce <elf_add+0xe4c>

000000000008e8fe <dwarf_lookup_pc>:
   8e8fe:	714d                	addi	sp,sp,-336
   8e900:	e686                	sd	ra,328(sp)
   8e902:	e2a2                	sd	s0,320(sp)
   8e904:	fe26                	sd	s1,312(sp)
   8e906:	fa4a                	sd	s2,304(sp)
   8e908:	f64e                	sd	s3,296(sp)
   8e90a:	f252                	sd	s4,288(sp)
   8e90c:	ee56                	sd	s5,280(sp)
   8e90e:	ea5a                	sd	s6,272(sp)
   8e910:	e65e                	sd	s7,264(sp)
   8e912:	e262                	sd	s8,256(sp)
   8e914:	fde6                	sd	s9,248(sp)
   8e916:	f9ea                	sd	s10,240(sp)
   8e918:	f5ee                	sd	s11,232(sp)
   8e91a:	4485                	li	s1,1
   8e91c:	547d                	li	s0,-1
   8e91e:	00982023          	sw	s1,0(a6)
   8e922:	1a860063          	beq	a2,s0,8eac2 <dwarf_lookup_pc+0x1c4>
   8e926:	7180                	ld	s0,32(a1)
   8e928:	18040d63          	beqz	s0,8eac2 <dwarf_lookup_pc+0x1c4>
   8e92c:	0185b883          	ld	a7,24(a1)
   8e930:	82c6                	mv	t0,a7
   8e932:	a809                	j	8e944 <dwarf_lookup_pc+0x46>
   8e934:	007634b3          	sltu	s1,a2,t2
   8e938:	0014c493          	xori	s1,s1,1
   8e93c:	8c05                	sub	s0,s0,s1
   8e93e:	8005                	srli	s0,s0,0x1
   8e940:	18040163          	beqz	s0,8eac2 <dwarf_lookup_pc+0x1c4>
   8e944:	00145493          	srli	s1,s0,0x1
   8e948:	00349313          	slli	t1,s1,0x3
   8e94c:	0496                	slli	s1,s1,0x5
   8e94e:	40648333          	sub	t1,s1,t1
   8e952:	9316                	add	t1,t1,t0
   8e954:	00033383          	ld	t2,0(t1)
   8e958:	00766663          	bltu	a2,t2,8e964 <dwarf_lookup_pc+0x66>
   8e95c:	01833483          	ld	s1,24(t1)
   8e960:	00c4f763          	bgeu	s1,a2,8e96e <dwarf_lookup_pc+0x70>
   8e964:	fc7668e3          	bltu	a2,t2,8e934 <dwarf_lookup_pc+0x36>
   8e968:	01830293          	addi	t0,t1,24
   8e96c:	b7e1                	j	8e934 <dwarf_lookup_pc+0x36>
   8e96e:	fe830d93          	addi	s11,t1,-24
   8e972:	030db403          	ld	s0,48(s11)
   8e976:	0de1                	addi	s11,s11,24
   8e978:	fe860de3          	beq	a2,s0,8e972 <dwarf_lookup_pc+0x74>
   8e97c:	a811                	j	8e990 <dwarf_lookup_pc+0x92>
   8e97e:	151d8263          	beq	s11,a7,8eac2 <dwarf_lookup_pc+0x1c4>
   8e982:	fe8db403          	ld	s0,-24(s11)
   8e986:	000db483          	ld	s1,0(s11)
   8e98a:	1da1                	addi	s11,s11,-24
   8e98c:	12946b63          	bltu	s0,s1,8eac2 <dwarf_lookup_pc+0x1c4>
   8e990:	008db403          	ld	s0,8(s11)
   8e994:	fe8675e3          	bgeu	a2,s0,8e97e <dwarf_lookup_pc+0x80>
   8e998:	010dbc83          	ld	s9,16(s11)
   8e99c:	080cb283          	ld	t0,128(s9)
   8e9a0:	080c8d13          	addi	s10,s9,128
   8e9a4:	fc96                	sd	t0,120(sp)
   8e9a6:	05b8f963          	bgeu	a7,s11,8e9f8 <dwarf_lookup_pc+0xfa>
   8e9aa:	fe8db483          	ld	s1,-24(s11)
   8e9ae:	04966563          	bltu	a2,s1,8e9f8 <dwarf_lookup_pc+0xfa>
   8e9b2:	ff8d8413          	addi	s0,s11,-8
   8e9b6:	58fd                	li	a7,-1
   8e9b8:	ff843483          	ld	s1,-8(s0)
   8e9bc:	02967c63          	bgeu	a2,s1,8e9f4 <dwarf_lookup_pc+0xf6>
   8e9c0:	4504                	lw	s1,8(a0)
   8e9c2:	c491                	beqz	s1,8e9ce <dwarf_lookup_pc+0xd0>
   8e9c4:	000d3283          	ld	t0,0(s10)
   8e9c8:	0230000f          	fence	r,rw
   8e9cc:	fc96                	sd	t0,120(sp)
   8e9ce:	03129363          	bne	t0,a7,8e9f4 <dwarf_lookup_pc+0xf6>
   8e9d2:	00043c83          	ld	s9,0(s0)
   8e9d6:	080cb283          	ld	t0,128(s9)
   8e9da:	6d84                	ld	s1,24(a1)
   8e9dc:	ff040d93          	addi	s11,s0,-16
   8e9e0:	080c8d13          	addi	s10,s9,128
   8e9e4:	fc96                	sd	t0,120(sp)
   8e9e6:	01b4f963          	bgeu	s1,s11,8e9f8 <dwarf_lookup_pc+0xfa>
   8e9ea:	fd843483          	ld	s1,-40(s0)
   8e9ee:	1421                	addi	s0,s0,-24
   8e9f0:	fc9674e3          	bgeu	a2,s1,8e9b8 <dwarf_lookup_pc+0xba>
   8e9f4:	00840d93          	addi	s11,s0,8
   8e9f8:	4504                	lw	s1,8(a0)
   8e9fa:	c491                	beqz	s1,8ea06 <dwarf_lookup_pc+0x108>
   8e9fc:	000d3283          	ld	t0,0(s10)
   8ea00:	0230000f          	fence	r,rw
   8ea04:	fc96                	sd	t0,120(sp)
   8ea06:	54fd                	li	s1,-1
   8ea08:	28928063          	beq	t0,s1,8ec88 <dwarf_lookup_pc+0x38a>
   8ea0c:	1a029263          	bnez	t0,8ebb0 <dwarf_lookup_pc+0x2b2>
   8ea10:	f042                	sd	a6,32(sp)
   8ea12:	ec32                	sd	a2,24(sp)
   8ea14:	e836                	sd	a3,16(sp)
   8ea16:	010db403          	ld	s0,16(s11)
   8ea1a:	86be                	mv	a3,a5
   8ea1c:	181c                	addi	a5,sp,48
   8ea1e:	07810813          	addi	a6,sp,120
   8ea22:	02810893          	addi	a7,sp,40
   8ea26:	8c2a                	mv	s8,a0
   8ea28:	8bae                	mv	s7,a1
   8ea2a:	89ba                	mv	s3,a4
   8ea2c:	863a                	mv	a2,a4
   8ea2e:	8a36                	mv	s4,a3
   8ea30:	8722                	mv	a4,s0
   8ea32:	374000ef          	jal	8eda6 <read_line_info>
   8ea36:	842a                	mv	s0,a0
   8ea38:	c55d                	beqz	a0,8eae6 <dwarf_lookup_pc+0x1e8>
   8ea3a:	e422                	sd	s0,8(sp)
   8ea3c:	87e2                	mv	a5,s8
   8ea3e:	008c2903          	lw	s2,8(s8)
   8ea42:	855e                	mv	a0,s7
   8ea44:	0d0b8b13          	addi	s6,s7,208
   8ea48:	012035b3          	snez	a1,s2
   8ea4c:	15fd                	addi	a1,a1,-1
   8ea4e:	010dba83          	ld	s5,16(s11)
   8ea52:	0165f5b3          	and	a1,a1,s6
   8ea56:	01858493          	addi	s1,a1,24
   8ea5a:	e026                	sd	s1,0(sp)
   8ea5c:	845a                	mv	s0,s6
   8ea5e:	00090d63          	beqz	s2,8ea78 <dwarf_lookup_pc+0x17a>
   8ea62:	09a4                	addi	s1,sp,216
   8ea64:	098c                	addi	a1,sp,208
   8ea66:	cd817057          	vsetivli	zero,2,e64,m1,ta,ma
   8ea6a:	5e003457          	vmv.v.i	v8,0
   8ea6e:	0205f427          	vse64.v	v8,(a1)
   8ea72:	0180                	addi	s0,sp,192
   8ea74:	02047427          	vse64.v	v8,(s0)
   8ea78:	7d0c                	ld	a1,56(a0)
   8ea7a:	0005c617          	auipc	a2,0x5c
   8ea7e:	c6a60613          	addi	a2,a2,-918 # ea6e4 <_ZZL13pch_open_fileP10cpp_readerP9_cpp_filePbE9extension+0x22c9>
   8ea82:	e132                	sd	a2,128(sp)
   8ea84:	e52e                	sd	a1,136(sp)
   8ea86:	cd817057          	vsetivli	zero,2,e64,m1,ta,ma
   8ea8a:	020af407          	vle64.v	v8,(s5)
   8ea8e:	0c852503          	lw	a0,200(a0)
   8ea92:	090c                	addi	a1,sp,144
   8ea94:	0205f427          	vse64.v	v8,(a1)
   8ea98:	d12a                	sw	a0,160(sp)
   8ea9a:	f54e                	sd	s3,168(sp)
   8ea9c:	f952                	sd	s4,176(sp)
   8ea9e:	dd02                	sw	zero,184(sp)
   8eaa0:	656a                	ld	a0,152(sp)
   8eaa2:	c529                	beqz	a0,8eaec <dwarf_lookup_pc+0x1ee>
   8eaa4:	0118                	addi	a4,sp,128
   8eaa6:	181c                	addi	a5,sp,48
   8eaa8:	8562                	mv	a0,s8
   8eaaa:	85de                	mv	a1,s7
   8eaac:	8656                	mv	a2,s5
   8eaae:	4681                	li	a3,0
   8eab0:	884e                	mv	a6,s3
   8eab2:	88d2                	mv	a7,s4
   8eab4:	8e22                	mv	t3,s0
   8eab6:	8ea2                	mv	t4,s0
   8eab8:	4b2010ef          	jal	8ff6a <read_function_entry>
   8eabc:	87e2                	mv	a5,s8
   8eabe:	f16d                	bnez	a0,8eaa0 <dwarf_lookup_pc+0x1a2>
   8eac0:	a88d                	j	8eb32 <dwarf_lookup_pc+0x234>
   8eac2:	4501                	li	a0,0
   8eac4:	00082023          	sw	zero,0(a6)
   8eac8:	60b6                	ld	ra,328(sp)
   8eaca:	6416                	ld	s0,320(sp)
   8eacc:	74f2                	ld	s1,312(sp)
   8eace:	7952                	ld	s2,304(sp)
   8ead0:	79b2                	ld	s3,296(sp)
   8ead2:	7a12                	ld	s4,288(sp)
   8ead4:	6af2                	ld	s5,280(sp)
   8ead6:	6b52                	ld	s6,272(sp)
   8ead8:	6bb2                	ld	s7,264(sp)
   8eada:	6c12                	ld	s8,256(sp)
   8eadc:	7cee                	ld	s9,248(sp)
   8eade:	7d4e                	ld	s10,240(sp)
   8eae0:	7dae                	ld	s11,232(sp)
   8eae2:	6171                	addi	sp,sp,336
   8eae4:	8082                	ret
   8eae6:	4b01                	li	s6,0
   8eae8:	4a81                	li	s5,0
   8eaea:	a88d                	j	8eb5c <dwarf_lookup_pc+0x25e>
   8eaec:	6088                	ld	a0,0(s1)
   8eaee:	c131                	beqz	a0,8eb32 <dwarf_lookup_pc+0x234>
   8eaf0:	45e1                	li	a1,24
   8eaf2:	853e                	mv	a0,a5
   8eaf4:	864e                	mv	a2,s3
   8eaf6:	86d2                	mv	a3,s4
   8eaf8:	8722                	mv	a4,s0
   8eafa:	bebf60ef          	jal	856e4 <backtrace_vector_grow>
   8eafe:	1e050763          	beqz	a0,8ecec <dwarf_lookup_pc+0x3ee>
   8eb02:	cc087057          	vsetivli	zero,16,e8,m1,ta,ma
   8eb06:	5e0fb457          	vmv.v.i	v8,-1
   8eb0a:	02050427          	vse8.v	v8,(a0)
   8eb0e:	00053823          	sd	zero,16(a0)
   8eb12:	0004ba83          	ld	s5,0(s1)
   8eb16:	24090663          	beqz	s2,8ed62 <dwarf_lookup_pc+0x464>
   8eb1a:	018c                	addi	a1,sp,192
   8eb1c:	8562                	mv	a0,s8
   8eb1e:	864e                	mv	a2,s3
   8eb20:	86d2                	mv	a3,s4
   8eb22:	c85f60ef          	jal	857a6 <backtrace_vector_release>
   8eb26:	1c050363          	beqz	a0,8ecec <dwarf_lookup_pc+0x3ee>
   8eb2a:	00043b03          	ld	s6,0(s0)
   8eb2e:	6422                	ld	s0,8(sp)
   8eb30:	a4a9                	j	8ed7a <dwarf_lookup_pc+0x47c>
   8eb32:	4b01                	li	s6,0
   8eb34:	4a81                	li	s5,0
   8eb36:	8752                	mv	a4,s4
   8eb38:	86ce                	mv	a3,s3
   8eb3a:	6422                	ld	s0,8(sp)
   8eb3c:	6666                	ld	a2,88(sp)
   8eb3e:	ca09                	beqz	a2,8eb50 <dwarf_lookup_pc+0x252>
   8eb40:	7586                	ld	a1,96(sp)
   8eb42:	060e                	slli	a2,a2,0x3
   8eb44:	8562                	mv	a0,s8
   8eb46:	af1f60ef          	jal	85636 <backtrace_free>
   8eb4a:	87e2                	mv	a5,s8
   8eb4c:	86ce                	mv	a3,s3
   8eb4e:	8752                	mv	a4,s4
   8eb50:	7626                	ld	a2,104(sp)
   8eb52:	75c6                	ld	a1,112(sp)
   8eb54:	060e                	slli	a2,a2,0x3
   8eb56:	853e                	mv	a0,a5
   8eb58:	adff60ef          	jal	85636 <backtrace_free>
   8eb5c:	8562                	mv	a0,s8
   8eb5e:	008c2703          	lw	a4,8(s8)
   8eb62:	66c2                	ld	a3,16(sp)
   8eb64:	6662                	ld	a2,24(sp)
   8eb66:	7802                	ld	a6,32(sp)
   8eb68:	c70d                	beqz	a4,8eb92 <dwarf_lookup_pc+0x294>
   8eb6a:	7722                	ld	a4,40(sp)
   8eb6c:	0310000f          	fence	rw,w
   8eb70:	08ecb423          	sd	a4,136(s9)
   8eb74:	0310000f          	fence	rw,w
   8eb78:	096cb823          	sd	s6,144(s9)
   8eb7c:	0310000f          	fence	rw,w
   8eb80:	095cbc23          	sd	s5,152(s9)
   8eb84:	7766                	ld	a4,120(sp)
   8eb86:	0310000f          	fence	rw,w
   8eb8a:	00ed3023          	sd	a4,0(s10)
   8eb8e:	72e6                	ld	t0,120(sp)
   8eb90:	a819                	j	8eba6 <dwarf_lookup_pc+0x2a8>
   8eb92:	7722                	ld	a4,40(sp)
   8eb94:	72e6                	ld	t0,120(sp)
   8eb96:	08ecb423          	sd	a4,136(s9)
   8eb9a:	096cb823          	sd	s6,144(s9)
   8eb9e:	095cbc23          	sd	s5,152(s9)
   8eba2:	005d3023          	sd	t0,0(s10)
   8eba6:	87d2                	mv	a5,s4
   8eba8:	874e                	mv	a4,s3
   8ebaa:	54fd                	li	s1,-1
   8ebac:	0c928963          	beq	t0,s1,8ec7e <dwarf_lookup_pc+0x380>
   8ebb0:	010db883          	ld	a7,16(s11)
   8ebb4:	0888b403          	ld	s0,136(a7)
   8ebb8:	ec51                	bnez	s0,8ec54 <dwarf_lookup_pc+0x356>
   8ebba:	0688b403          	ld	s0,104(a7)
   8ebbe:	e041                	bnez	s0,8ec3e <dwarf_lookup_pc+0x340>
   8ebc0:	0588b403          	ld	s0,88(a7)
   8ebc4:	c83d                	beqz	s0,8ec3a <dwarf_lookup_pc+0x33c>
   8ebc6:	00044583          	lbu	a1,0(s0)
   8ebca:	02f00493          	li	s1,47
   8ebce:	06958663          	beq	a1,s1,8ec3a <dwarf_lookup_pc+0x33c>
   8ebd2:	0608bb83          	ld	s7,96(a7)
   8ebd6:	060b8263          	beqz	s7,8ec3a <dwarf_lookup_pc+0x33c>
   8ebda:	8d42                	mv	s10,a6
   8ebdc:	8c32                	mv	s8,a2
   8ebde:	8cb6                	mv	s9,a3
   8ebe0:	8a2a                	mv	s4,a0
   8ebe2:	8522                	mv	a0,s0
   8ebe4:	8abe                	mv	s5,a5
   8ebe6:	8b3a                	mv	s6,a4
   8ebe8:	c48850ef          	jal	14030 <strlen@plt>
   8ebec:	892a                	mv	s2,a0
   8ebee:	855e                	mv	a0,s7
   8ebf0:	c40850ef          	jal	14030 <strlen@plt>
   8ebf4:	89aa                	mv	s3,a0
   8ebf6:	00a905b3          	add	a1,s2,a0
   8ebfa:	0589                	addi	a1,a1,2
   8ebfc:	8552                	mv	a0,s4
   8ebfe:	865a                	mv	a2,s6
   8ec00:	8b56                	mv	s6,s5
   8ec02:	86d6                	mv	a3,s5
   8ec04:	911f60ef          	jal	85514 <backtrace_alloc>
   8ec08:	18050963          	beqz	a0,8ed9a <dwarf_lookup_pc+0x49c>
   8ec0c:	8a2a                	mv	s4,a0
   8ec0e:	85de                	mv	a1,s7
   8ec10:	864e                	mv	a2,s3
   8ec12:	89f850ef          	jal	144b0 <memcpy@plt>
   8ec16:	013a0533          	add	a0,s4,s3
   8ec1a:	02f00593          	li	a1,47
   8ec1e:	00b50023          	sb	a1,0(a0)
   8ec22:	0505                	addi	a0,a0,1
   8ec24:	00190613          	addi	a2,s2,1
   8ec28:	85a2                	mv	a1,s0
   8ec2a:	887850ef          	jal	144b0 <memcpy@plt>
   8ec2e:	010db883          	ld	a7,16(s11)
   8ec32:	8452                	mv	s0,s4
   8ec34:	86e6                	mv	a3,s9
   8ec36:	8662                	mv	a2,s8
   8ec38:	87da                	mv	a5,s6
   8ec3a:	0688b423          	sd	s0,104(a7)
   8ec3e:	853e                	mv	a0,a5
   8ec40:	85b2                	mv	a1,a2
   8ec42:	8622                	mv	a2,s0
   8ec44:	a0a9                	j	8ec8e <dwarf_lookup_pc+0x390>
   8ec46:	00b635b3          	sltu	a1,a2,a1
   8ec4a:	0015c593          	xori	a1,a1,1
   8ec4e:	8c0d                	sub	s0,s0,a1
   8ec50:	8005                	srli	s0,s0,0x1
   8ec52:	d425                	beqz	s0,8ebba <dwarf_lookup_pc+0x2bc>
   8ec54:	00145593          	srli	a1,s0,0x1
   8ec58:	00359493          	slli	s1,a1,0x3
   8ec5c:	0596                	slli	a1,a1,0x5
   8ec5e:	8d85                	sub	a1,a1,s1
   8ec60:	00b28333          	add	t1,t0,a1
   8ec64:	00033583          	ld	a1,0(t1)
   8ec68:	00b66663          	bltu	a2,a1,8ec74 <dwarf_lookup_pc+0x376>
   8ec6c:	01833483          	ld	s1,24(t1)
   8ec70:	02966463          	bltu	a2,s1,8ec98 <dwarf_lookup_pc+0x39a>
   8ec74:	fcb669e3          	bltu	a2,a1,8ec46 <dwarf_lookup_pc+0x348>
   8ec78:	01830293          	addi	t0,t1,24
   8ec7c:	b7e9                	j	8ec46 <dwarf_lookup_pc+0x348>
   8ec7e:	c409                	beqz	s0,8ec88 <dwarf_lookup_pc+0x38a>
   8ec80:	85de                	mv	a1,s7
   8ec82:	c7dff0ef          	jal	8e8fe <dwarf_lookup_pc>
   8ec86:	b589                	j	8eac8 <dwarf_lookup_pc+0x1ca>
   8ec88:	853e                	mv	a0,a5
   8ec8a:	85b2                	mv	a1,a2
   8ec8c:	4601                	li	a2,0
   8ec8e:	87b6                	mv	a5,a3
   8ec90:	4681                	li	a3,0
   8ec92:	4701                	li	a4,0
   8ec94:	9782                	jalr	a5
   8ec96:	bd0d                	j	8eac8 <dwarf_lookup_pc+0x1ca>
   8ec98:	0988b703          	ld	a4,152(a7)
   8ec9c:	cf15                	beqz	a4,8ecd8 <dwarf_lookup_pc+0x3da>
   8ec9e:	0908b803          	ld	a6,144(a7)
   8eca2:	84c2                	mv	s1,a6
   8eca4:	a801                	j	8ecb4 <dwarf_lookup_pc+0x3b6>
   8eca6:	00b63533          	sltu	a0,a2,a1
   8ecaa:	00154513          	xori	a0,a0,1
   8ecae:	8f09                	sub	a4,a4,a0
   8ecb0:	8305                	srli	a4,a4,0x1
   8ecb2:	c31d                	beqz	a4,8ecd8 <dwarf_lookup_pc+0x3da>
   8ecb4:	00175513          	srli	a0,a4,0x1
   8ecb8:	00351593          	slli	a1,a0,0x3
   8ecbc:	0516                	slli	a0,a0,0x5
   8ecbe:	8d0d                	sub	a0,a0,a1
   8ecc0:	9526                	add	a0,a0,s1
   8ecc2:	610c                	ld	a1,0(a0)
   8ecc4:	00b66563          	bltu	a2,a1,8ecce <dwarf_lookup_pc+0x3d0>
   8ecc8:	6d00                	ld	s0,24(a0)
   8ecca:	02c47763          	bgeu	s0,a2,8ecf8 <dwarf_lookup_pc+0x3fa>
   8ecce:	fcb66ce3          	bltu	a2,a1,8eca6 <dwarf_lookup_pc+0x3a8>
   8ecd2:	01850493          	addi	s1,a0,24
   8ecd6:	bfc1                	j	8eca6 <dwarf_lookup_pc+0x3a8>
   8ecd8:	00833703          	ld	a4,8(t1)
   8ecdc:	01032483          	lw	s1,16(t1)
   8ece0:	853e                	mv	a0,a5
   8ece2:	85b2                	mv	a1,a2
   8ece4:	863a                	mv	a2,a4
   8ece6:	87b6                	mv	a5,a3
   8ece8:	86a6                	mv	a3,s1
   8ecea:	b765                	j	8ec92 <dwarf_lookup_pc+0x394>
   8ecec:	4b01                	li	s6,0
   8ecee:	4a81                	li	s5,0
   8ecf0:	8752                	mv	a4,s4
   8ecf2:	86ce                	mv	a3,s3
   8ecf4:	87e2                	mv	a5,s8
   8ecf6:	b591                	j	8eb3a <dwarf_lookup_pc+0x23c>
   8ecf8:	84b6                	mv	s1,a3
   8ecfa:	1521                	addi	a0,a0,-24
   8ecfc:	790c                	ld	a1,48(a0)
   8ecfe:	0561                	addi	a0,a0,24
   8ed00:	feb60ee3          	beq	a2,a1,8ecfc <dwarf_lookup_pc+0x3fe>
   8ed04:	a809                	j	8ed16 <dwarf_lookup_pc+0x418>
   8ed06:	05050463          	beq	a0,a6,8ed4e <dwarf_lookup_pc+0x450>
   8ed0a:	fe853583          	ld	a1,-24(a0)
   8ed0e:	6114                	ld	a3,0(a0)
   8ed10:	1521                	addi	a0,a0,-24
   8ed12:	02d5ee63          	bltu	a1,a3,8ed4e <dwarf_lookup_pc+0x450>
   8ed16:	650c                	ld	a1,8(a0)
   8ed18:	feb677e3          	bgeu	a2,a1,8ed06 <dwarf_lookup_pc+0x408>
   8ed1c:	00833583          	ld	a1,8(t1)
   8ed20:	6900                	ld	s0,16(a0)
   8ed22:	f82e                	sd	a1,48(sp)
   8ed24:	01032503          	lw	a0,16(t1)
   8ed28:	c12a                	sw	a0,128(sp)
   8ed2a:	1818                	addi	a4,sp,48
   8ed2c:	86be                	mv	a3,a5
   8ed2e:	011c                	addi	a5,sp,128
   8ed30:	8932                	mv	s2,a2
   8ed32:	8532                	mv	a0,a2
   8ed34:	85a2                	mv	a1,s0
   8ed36:	8626                	mv	a2,s1
   8ed38:	89b6                	mv	s3,a3
   8ed3a:	65b000ef          	jal	8fb94 <report_inlined_functions>
   8ed3e:	d80515e3          	bnez	a0,8eac8 <dwarf_lookup_pc+0x1ca>
   8ed42:	7642                	ld	a2,48(sp)
   8ed44:	468a                	lw	a3,128(sp)
   8ed46:	6018                	ld	a4,0(s0)
   8ed48:	854e                	mv	a0,s3
   8ed4a:	85ca                	mv	a1,s2
   8ed4c:	a809                	j	8ed5e <dwarf_lookup_pc+0x460>
   8ed4e:	00833703          	ld	a4,8(t1)
   8ed52:	01032683          	lw	a3,16(t1)
   8ed56:	853e                	mv	a0,a5
   8ed58:	85b2                	mv	a1,a2
   8ed5a:	863a                	mv	a2,a4
   8ed5c:	4701                	li	a4,0
   8ed5e:	9482                	jalr	s1
   8ed60:	b3a5                	j	8eac8 <dwarf_lookup_pc+0x1ca>
   8ed62:	8562                	mv	a0,s8
   8ed64:	85da                	mv	a1,s6
   8ed66:	864e                	mv	a2,s3
   8ed68:	86d2                	mv	a3,s4
   8ed6a:	a2ff60ef          	jal	85798 <backtrace_vector_finish>
   8ed6e:	6422                	ld	s0,8(sp)
   8ed70:	c905                	beqz	a0,8eda0 <dwarf_lookup_pc+0x4a2>
   8ed72:	8b2a                	mv	s6,a0
   8ed74:	6502                	ld	a0,0(sp)
   8ed76:	00053023          	sd	zero,0(a0)
   8ed7a:	00001517          	auipc	a0,0x1
   8ed7e:	75850693          	addi	a3,a0,1880 # 904d2 <function_addrs_compare>
   8ed82:	4661                	li	a2,24
   8ed84:	855a                	mv	a0,s6
   8ed86:	85d6                	mv	a1,s5
   8ed88:	2a7010ef          	jal	9082e <backtrace_qsort>
   8ed8c:	8752                	mv	a4,s4
   8ed8e:	86ce                	mv	a3,s3
   8ed90:	87e2                	mv	a5,s8
   8ed92:	6666                	ld	a2,88(sp)
   8ed94:	da0616e3          	bnez	a2,8eb40 <dwarf_lookup_pc+0x242>
   8ed98:	bb65                	j	8eb50 <dwarf_lookup_pc+0x252>
   8ed9a:	000d2023          	sw	zero,0(s10)
   8ed9e:	b32d                	j	8eac8 <dwarf_lookup_pc+0x1ca>
   8eda0:	4b01                	li	s6,0
   8eda2:	4a81                	li	s5,0
   8eda4:	b7e5                	j	8ed8c <dwarf_lookup_pc+0x48e>

00000000000996fe <d_count_templates_scopes>:
   996fe:	1101                	addi	sp,sp,-32
   99700:	ec06                	sd	ra,24(sp)
   99702:	e822                	sd	s0,16(sp)
   99704:	e426                	sd	s1,8(sp)
   99706:	c5c1                	beqz	a1,9978e <d_count_templates_scopes+0x90>
   99708:	4285                	li	t0,1
   9970a:	40000893          	li	a7,1024
   9970e:	05d00813          	li	a6,93
   99712:	000ee717          	auipc	a4,0xee
   99716:	2ca70793          	addi	a5,a4,714 # 1879dc <elf_crc32.crc32_table+0x11f4>
   9971a:	4598                	lw	a4,8(a1)
   9971c:	06e2c963          	blt	t0,a4,9978e <d_count_templates_scopes+0x90>
   99720:	13452403          	lw	s0,308(a0)
   99724:	0688c563          	blt	a7,s0,9978e <d_count_templates_scopes+0x90>
   99728:	4194                	lw	a3,0(a1)
   9972a:	00170613          	addi	a2,a4,1
   9972e:	fff68713          	addi	a4,a3,-1
   99732:	c590                	sw	a2,8(a1)
   99734:	04e86d63          	bltu	a6,a4,9978e <d_count_templates_scopes+0x90>
   99738:	070a                	slli	a4,a4,0x2
   9973a:	973e                	add	a4,a4,a5
   9973c:	4310                	lw	a2,0(a4)
   9973e:	963e                	add	a2,a2,a5
   99740:	4761                	li	a4,24
   99742:	8602                	jr	a2
   99744:	4741                	li	a4,16
   99746:	95ba                	add	a1,a1,a4
   99748:	618c                	ld	a1,0(a1)
   9974a:	f9e1                	bnez	a1,9971a <d_count_templates_scopes+0x1c>
   9974c:	a089                	j	9978e <d_count_templates_scopes+0x90>
   9974e:	6990                	ld	a2,16(a1)
   99750:	4210                	lw	a2,0(a2)
   99752:	4695                	li	a3,5
   99754:	00d61b63          	bne	a2,a3,9976a <d_count_templates_scopes+0x6c>
   99758:	15c00613          	li	a2,348
   9975c:	a019                	j	99762 <d_count_templates_scopes+0x64>
   9975e:	16c00613          	li	a2,364
   99762:	962a                	add	a2,a2,a0
   99764:	4214                	lw	a3,0(a2)
   99766:	0685                	addi	a3,a3,1
   99768:	c214                	sw	a3,0(a2)
   9976a:	0405                	addi	s0,s0,1
   9976c:	12852a23          	sw	s0,308(a0)
   99770:	6990                	ld	a2,16(a1)
   99772:	842a                	mv	s0,a0
   99774:	84ae                	mv	s1,a1
   99776:	85b2                	mv	a1,a2
   99778:	f87ff0ef          	jal	996fe <d_count_templates_scopes>
   9977c:	6c8c                	ld	a1,24(s1)
   9977e:	8522                	mv	a0,s0
   99780:	f7fff0ef          	jal	996fe <d_count_templates_scopes>
   99784:	13442503          	lw	a0,308(s0)
   99788:	157d                	addi	a0,a0,-1
   9978a:	12a42a23          	sw	a0,308(s0)
   9978e:	60e2                	ld	ra,24(sp)
   99790:	6442                	ld	s0,16(sp)
   99792:	64a2                	ld	s1,8(sp)
   99794:	6105                	addi	sp,sp,32
   99796:	8082                	ret

"""


@lru_cache(maxsize=2)
def load_recursive_program():
    """Parse the recursive-call extract into a CFG-backed ``Program``."""

    from chimera.preprocess.offline.analysis.arch.riscv.rvv.services import (
        RvvServices,
    )
    from chimera.preprocess.offline.analysis.arch.riscv.services import (
        RiscvServices,
    )
    from chimera.preprocess.offline.analysis.program_model.parser import parse_dump
    from chimera.preprocess.offline.analysis.toolchain.objdump import LinuxObjdump

    adapter = LinuxObjdump("objdump")
    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory) / "recursive.dump"
        source.write_text(RECURSIVE_FUNCTIONS_DUMP, encoding="utf-8")
        parsed = parse_dump(
            source,
            adapter.parse_format,
            is_external_trampoline=adapter.is_external_trampoline,
            retain_dump_lines=False,
        )
    return RiscvServices(RvvServices()).build_cfg(parsed)


# endregion


__all__ = [
    "ADJUSTED_ERROR_CALLS",
    "ALL_FUNCTIONS",
    "CLOSE_AT_FILE",
    "DEMANGLE_ALLOCATIONS",
    "DEMANGLE_CALLBACK_CALL",
    "DEMANGLE_COUNT_CALLEE",
    "DEMANGLE_PRINT_CALLBACK",
    "DEMANGLE_RELEASE",
    "DESTRINGIZE_ALLOA_SITE",
    "DESTRINGIZE_ALLOCATION",
    "DESTRINGIZE_AND_RUN",
    "DESTRINGIZE_CALL",
    "DESTRINGIZE_LENGTH_LOAD",
    "DESTRINGIZE_RELEASE",
    "DYNAMIC_ADJUSTMENT",
    "FOLLOWUP_FUNCTIONS",
    "FOLLOWUP_FUNCTIONS_DUMP",
    "SET_UP_SPECS",
    "SET_UP_SPECS_ALLOCA_SITE",
    "SET_UP_SPECS_ALLOCATION",
    "SET_UP_SPECS_CALL",
    "SET_UP_SPECS_RELEASE",
    "SET_UP_SPECS_STRLEN_CALL",
    "load_followup_program",
    "FIXED_FRAME_FUNCTIONS",
    "FRAME_RELEASE",
    "FRAME_RESTORE",
    "INDEPENDENT_ERROR_CALL",
    "SEED_CALL_SITES",
    "STACK_FUNCTIONS_DUMP",
    "STUB_CALLEE",
    "STUB_CALLEE_ADDRESS",
    "STUB_CALLEE_DUMP",
    "function",
    "load_program",
    "D_COUNT_TEMPLATES_SCOPES",
    "D_COUNT_TEMPLATES_SCOPES_ALLOCATION",
    "D_COUNT_TEMPLATES_SCOPES_JUMP_TABLE",
    "D_COUNT_TEMPLATES_SCOPES_RECURSIVE_CALLS",
    "D_COUNT_TEMPLATES_SCOPES_RESTORE",
    "DWARF_LOOKUP_PC",
    "DWARF_LOOKUP_PC_ALLOCATION",
    "DWARF_LOOKUP_PC_INDIRECT_CALLS",
    "DWARF_LOOKUP_PC_RECURSIVE_CALL",
    "DWARF_LOOKUP_PC_RESTORE",
    "DWARF_LOOKUP_PC_VECTOR_STORES",
    "ELF_ADD",
    "ELF_ADD_ALLOCATION",
    "ELF_ADD_INDIRECT_CALLS",
    "ELF_ADD_RECURSIVE_CALLS",
    "ELF_ADD_RESTORE",
    "RECURSIVE_FUNCTIONS",
    "RECURSIVE_FUNCTIONS_DUMP",
    "load_recursive_program",
]

