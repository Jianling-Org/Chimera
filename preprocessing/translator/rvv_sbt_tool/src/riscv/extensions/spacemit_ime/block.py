"""Local native-register frame; no persistent simulated vector state."""

from dataclasses import dataclass

GPRS = tuple(f"t{i}" for i in range(7))
VL_OFFSET = 56
VTYPE_OFFSET = 64
TEMP_BASE = 80


@dataclass(frozen=True)
class FrameLayout:
    """Snapshot the complete A group, followed by B and the destination group.

    All slots are whole 128-byte registers. The scalar header is 16-byte
    aligned, so single/pair destinations and sliding inputs preserve stack alignment.
    """

    a_registers: tuple[str, ...]
    destination_count: int
    temporary_count: int = 3
    saved_gprs: tuple[str, ...] = GPRS
    changes_configuration: bool = True

    @property
    def temporary_offsets(self) -> dict[str, int]:
        return {f"v{i}": TEMP_BASE + 128 * i for i in range(self.temporary_count)}

    @property
    def a_offset(self) -> int:
        return TEMP_BASE + 128 * self.temporary_count

    @property
    def b_offset(self) -> int:
        return self.a_offset + 128 * len(self.a_registers)

    @property
    def c_offset(self) -> int:
        return self.b_offset + 128

    @property
    def size(self) -> int:
        return self.c_offset + 128 * self.destination_count


def address(offset: int) -> str:
    return f"    addi t0, sp, {offset}"


def restore_gprs(frame: FrameLayout) -> list[str]:
    return [*(f"    ld {reg}, {i * 8}(sp)" for i, reg in enumerate(frame.saved_gprs)),
            f"    addi sp, sp, {frame.size}"]


def begin(frame: FrameLayout, vd: str, vs2: str, fail: str, *, snapshot_destination: bool = True) -> list[str]:
    lines = [f"    addi sp, sp, -{frame.size}"]
    lines += [f"    sd {reg}, {i * 8}(sp)" for i, reg in enumerate(frame.saved_gprs)]
    # Guards precede vector stores and configuration changes. Rejection restores
    # every register we touched, including sp, before raising an illegal opcode.
    lines += [
        "    csrr t0, vlenb", "    li t1, 128", f"    bne t0, t1, {fail}",
        "    csrr t0, vstart", f"    bnez t0, {fail}",
        "    csrr t0, vtype", f"    bltz t0, {fail}",
        "    andi t1, t0, 7", f"    bnez t1, {fail}",
    ]
    if frame.changes_configuration:
        lines += [f"    sd t0, {VTYPE_OFFSET}(sp)",
                  "    csrr t0, vl", f"    sd t0, {VL_OFFSET}(sp)"]
    else:
        # Snapshot addressing uses only t0. Keep the original vtype in t1
        # for a configuration-preserving body's local width dispatch.
        lines.append("    mv t1, t0")
    for reg, offset in frame.temporary_offsets.items():
        lines += [address(offset), f"    vs1r.v {reg}, (t0)"]
    # Snapshot operands before borrowing any temporary: sources/destinations
    # may use those registers, and vs1 may equal vs2.
    snapshots = [(reg, frame.a_offset + 128 * i) for i, reg in enumerate(frame.a_registers)]
    snapshots.append((vs2, frame.b_offset))
    if snapshot_destination:
        snapshots += [(f"v{int(vd[1:]) + i}", frame.c_offset + 128 * i)
                      for i in range(frame.destination_count)]
    for reg, offset in snapshots:
        lines += [address(offset), f"    vs1r.v {reg}, (t0)"]
    return lines


def end(frame: FrameLayout, vd: str, fail: str, done: str, *,
        writeback_destination: bool = True) -> list[str]:
    lines = []
    for reg, offset in frame.temporary_offsets.items():
        lines += [address(offset), f"    vl1re8.v {reg}, (t0)"]
    # Restore temporaries first; destination writes must win on overlap.
    if writeback_destination:
        for i in range(frame.destination_count):
            reg, offset = f"v{int(vd[1:]) + i}", frame.c_offset + 128 * i
            lines += [address(offset), f"    vl1re8.v {reg}, (t0)"]
    if frame.changes_configuration:
        lines += [f"    ld t0, {VL_OFFSET}(sp)", f"    ld t1, {VTYPE_OFFSET}(sp)",
                  "    vsetvl zero, t0, t1"]
    lines += [*restore_gprs(frame), f"    j {done}",
              f"{fail}:", *restore_gprs(frame), "    unimp", f"{done}:"]
    return lines
