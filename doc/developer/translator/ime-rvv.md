# A100 IME to native RVV

This fourth entry expands A100 IME instructions into standard RVV with
VLEN=1024. Both source and target use the A100 vector-register layout.
The specification is [SpacemiT IME profile v0.6](https://github.com/spacemit-com/docs-ai/blob/main/en/architecture/ime_extension.md),
sections 2, 5.1, 5.2, 7 and 8. This is not the RVV256-to-RVV1024 transition backend.

```sh
python3 ime_sbt_rvv.py kernel.s -o kernel_rvv.s
```

The Python entry is `ime_sbt_rvv.translate_assembly(source)`.

## Supported input

- Pre-expanded symbolic assembly, with one instruction per line; inline labels
  and normal assembler directives/relocations are retained.
- Base `smt.vmadot`, `smt.vmadotu`, `smt.vmadotus`, `smt.vmadotsu`, each with
  explicit `vd, vs1, vs2, i4` or `vd, vs1, vs2, i8` operands: eight forms.
- Sliding-window `smt.vmadot1`, `smt.vmadot2`, `smt.vmadot3`, each with the same
  signedness suffixes (empty, `u`, `us`, `su`) and explicit `i8`: twelve forms.
  Int4 sliding-window forms are not defined and are rejected.
- Destination must be even and its two registers must not overlap any source.
  Sliding-window vs1 must be even, and vs1/vs1+1 form the complete A source.
  The sources may overlap each other, including vs2=vs1 or vs2=vs1+1.
- Layout instructions: `smt.vpack.vv`, `smt.vupack.vv`, `smt.vnpack.vv`,
  `smt.vnspack.vv`, `smt.vnpack4.vv`, `smt.vnspack4.vv`, all with explicit
  `vd, vs1, vs2, imm2` and imm2 in 0-3. Pack/unpack require even vd and produce
  vd/vd+1. Narrowing produces only vd, which may be any v0-v31. Source and
  destination overlaps are allowed and use pre-instruction source snapshots.
- Scalar and standard RVV instructions remain native. The assembler/linker
  resolves symbolic branches and relocations after expansion.
- Unknown `smt.*`, other IME families, legacy unprefixed spellings, raw
  instruction encodings, macros/includes/assembler conditionals and objdump
  input are rejected. Pre-expand macros before using this entry.

This source-assembly entry does not generate a Chimera Runtime offset map or
reuse a migration lookup profile. Relocated objdump/ELF integration is outside
this first implementation. It does not alter the existing three public entries.

## Execution and state contract

Int8 expands an 8x16 by 16x8 product into a full 8x8 Int32 accumulator; Int4 uses
8x32 by 32x8. Arithmetic is modulo 2^32. A and the column-wise B vectors occupy
128 bytes each for the base forms; the accumulator occupies 256 bytes.
Int4 element 2n is the low nibble of byte n and element 2n+1 is the high nibble.
Each nibble is sign/zero-extended independently before accumulation.
Signedness follows the mnemonic:
signed/signed, unsigned/unsigned, unsigned/signed, signed/unsigned respectively.

Sliding-window A reads start at byte offsets 16/32/48 for slide 1/2/3. Both A
registers are snapshotted; the last rows cross into vs1+1. B and the accumulator
retain the Int8 base geometry. The complete source group participates in
operand validation and semantic input metadata.

The block guards `vlenb==128`, legal `vtype`, `LMUL==1`, and `vstart==0` before
touching vector registers. Failure restores borrowed GPRs and sp, then executes
an illegal instruction. This is an unsupported-configuration rejection, not a
claim about how the hardware IME behaves for those configurations.

The lowering follows the specification's full-tile pseudocode, independently of
the incoming `vl`. It preserves incoming `vl/vtype` exactly. Tests with short or
zero vl verify this chosen lowering contract; they do not establish native IME
behavior for those cases. Native integer comparison covers full-length
e8/e16/e32/e64, LMUL=1, all tail/mask policies, and zero vstart.

The 16-byte-aligned stack frame holds t0-t6, vl/vtype, whole-register copies of
the borrowed vectors, all source registers, and reserved accumulator space.
Int8 borrows v0-v6: its frame is 1488 bytes for base forms and 1616 bytes for
sliding-window forms. Int4 retains v0-v2 and its 976-byte frame. A/B/C offsets
are derived from the temporary count and number of A registers.
Every input is snapshotted before any temporary is borrowed. Integer
multiply-adds do not modify vcsr or fcsr. Temporary vectors are restored before
final destination writeback, including when vd/vd+1 overlaps v0-v6. All
non-output vector bits, including tails, all GPRs/FPRs, and sp survive the block.

Int8 transposes the two byte matrices once into K-major working copies in their
stack slots. Packed scalar words are broadcast and shifted into 32 e32 lanes,
each representing four output rows by eight columns. Each K constructs B once
and reuses it for the two output groups. Byte extraction shifts left by
24 minus the byte offset, then right by 24 with sign/zero extension.
When vd/vd+1 are disjoint from v0-v6 (legal even vd >= 8), MACs update those
architectural registers directly, avoiding the old-C snapshot, C working
load/store, and destination reload. Conflicting destinations retain v4/v5
accumulators and the original writeback order. Frame sizes remain unchanged.
The choice depends only on this instruction, and every block restores its
complete borrowed state before the next source instruction. A complete IME performs 32
VL=32 MACs instead of 128 VL=8 MACs, with no vector load, gather or configuration
change inside the K loop. The slide offset only changes the initial A window.
All sixteen Int8 forms share this computation; Int4 retains its previous algorithm.

The frame is per invocation; there is no TLS simulated vector state. Normal
OS interrupt save/restore is compatible with execution, but migration,
unwinding, or source-instruction recovery from the middle of an expansion is
not implemented. Stack space must be available. Source boundary state is the
supported observation point.

## Layout instruction profile and index normalization

The six mnemonics are implemented for LMUL=1, VLEN=1024, and zero vstart.
Other LMUL configurations are rejected as outside this implementation profile,
not declared illegal by the ISA. Their source/destination grouping is not
inferred from the matrix instructions. Like the integer path, layout operations
process the complete documented register payload independently of incoming vl.

| Instructions | Incoming SEW | Source width | Output width | Result bytes |
|---|---|---|---|---|
| vpack / vupack | 8, 16, 32, 64 | unchanged bits | unchanged bits | 256 |
| vnpack / vnspack | 8, 16, 32 | 2 x SEW | SEW | 128 |
| vnpack4 / vnspack4 | 8 | 8 | 4 | 128 |

For pack/unpack, imm2 0 uses SEW-bit chunks, while 1/2/3 use 128/256/512-bit
chunks. The two source streams are interleaved into a contiguous pair for pack.
Unpack extracts even chunks of concatenated vs1/vs2 into vd and odd chunks into
vd+1. It is the inverse of pack, including when either destination overlaps a source.

For narrowing, imm2 0/1/2/3 selects 32/64/128/256 input bits per source chunk.
Each narrowed A chunk is followed by its narrowed B chunk. A chunk must contain
at least one complete source element; e32 vnpack/vnspack with imm2=0 is rejected.
The half-width interpretation follows the `SEW = 2 * SEW` step in section 7.5:
incoming vtype.SEW is the output width. 128-bit sources (incoming e64) are not
implemented. The nibble path currently implements only 8-to-4 narrowing at e8.

Saturating forms implement the signed SCLIP formula in section 7.2.2. They use
signed min/max followed by truncation, preserve vxrm/vxsat, and do not introduce
vnclip's rounding or sticky-saturation side effects. Unsigned interpretation
and other width/grouping profiles are not silently inferred.

The document's pseudocode has dimensional inconsistencies: pack uses a bit
offset as an element index, unpack omits divisions by SEW in destination indices,
and nibble packing resets `out` within each chunk and gives a pair count that
would overread an 8-bit source. This implementation normalizes all addresses
to byte/element units according to the textual descriptions and register sizes:
an input chunk of P bits narrows to P/2 output bits; adjacent nibble elements
become low/high halves of one byte; output advances across all chunks.
These are explicit implementation interpretations, not hardware-confirmed
corrections to the specification. QEMU tests validate this contract, while native
A100 comparison remains necessary to confirm the hardware uses the same rules.
In the expanded native state suite, `smt.vpack.vv v0,v0,v1,0` raises SIGILL on
the tested A100. Layout overlap support is therefore still a software contract,
not a hardware-validated configuration; the Int8 optimization leaves it unchanged.

Pack uses aligned scalar copies of the input snapshots, so it borrows no vector
registers and does not snapshot the old destination. It writes all 256 result
bytes before destination writeback, including for overlapping operands; its
frame is 592 bytes. Unpack retains the 976-byte frame, and single-register
narrowing retains 848 bytes. All input snapshots precede temporary use, and unsupported
width guards occur before any vector calculation. Successful blocks preserve
vl/vtype and all non-output physical state, including vcsr and fcsr.

Pack saves only t0/t1. Its single vtype read is retained in t1 for local dispatch.
Scalar copies and whole-register transfers do not change
vl/vtype, so pack neither saves nor rewrites these CSRs; the vstart==0 guard
ensures whole-register transfers also preserve vstart. Other GPRs are untouched.
Nonzero pack immediates select a fixed chunk width, with one payload after a
supported-SEW check; imm=0 retains its SEW dispatch. Every source instruction
still owns its guards, snapshots, writeback and GPR/sp restoration. No state
or transformed operand is reused across source-instruction boundaries.

## Architecture

`spacemit_ime/translation.py` retains source text and uses the existing
`TranslationPipeline.prepare`, strict preflight and fresh `EmissionSession`.
`backend.py` supplies `InstructionSpec -> LoweringPlan -> LoweringResult` through
the existing registry. Its native context has no simulated-state layout.
Integer mode metadata records signedness and slide; the validated type operand
selects Int4 or Int8. `rearrange.py` owns layout-specific validation and lowering.
`block.py` owns the physical-register frame and guards. RVV configuration is
preserved at runtime rather than inferred from potentially incomplete CFG facts.

See `verify/ime_rvv/README.md` for execution and full-state checks. Host pytest
and standard QEMU cannot replace native A100 IME comparison.

## A100 operator validation

The IME GEMM benchmark extracts `gemm_kernel_i8i3k_m4` from user-supplied llama.cpp sources. See the [benchmark preparation instructions](../../../preprocessing/translator/rvv_sbt_tool/verify/ime_q3_gemm/README.md). Historical A100 measurements and intermediate optimization artifacts are not distributed here. Re-run state checks on the target hardware before making hardware-equivalence or performance claims.
