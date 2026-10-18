# BPF map schema

The pinned uprobe queue uses a 32-bit little-endian opaque key and the
176-byte `struct chimera_uprobe_info` declared in
`runtime/interfaces/uapi/chimera_uprobe.h`. Python uses the matching
`<Q20QiB3x` layout and tests it against a golden byte sample.
