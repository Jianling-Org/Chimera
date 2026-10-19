#!/usr/bin/env python3
"""Clean RVV LLVM IR text for SVF consumption.

Rewrites scalable-vector types to fixed-length ones and renames RISC-V
intrinsics (same logic as the inline cleaner in build_opencv_real_ifaces.sh):
  <vscale x N x T>   -> <N x T>
  @llvm.riscv.foo    -> @__riscv_foo
  ' immarg'          -> removed (older llvm-as rejects the attribute)

Usage: clean_rvv_ir.py <file.ll> [<file.ll> ...]   (in place)
"""
import re
import sys


def clean_text(text):
    def fix_scalable(m):
        inner = m.group(0)[len('<vscale x '):-1]
        parts = inner.split(' x ', 1)
        return "<" + parts[0] + " x " + parts[1] + ">" if len(parts) == 2 else m.group(0)

    text = re.sub(r'<vscale x [^>]+>', fix_scalable, text)
    # RVV tuple target-extension types (clang>=19 on newer RVV code):
    #   target("riscv.vector.tuple", <N x T>, K) -> [K x <N x T>]
    # (after the vscale rewrite above, so the inner vector is already fixed)
    text = re.sub(r'target\("riscv\.vector\.tuple",\s*(<[^>]+>),\s*(\d+)\)',
                  r'[\2 x \1]', text)
    text = re.sub(r'@llvm\.riscv\.(\w+)', r'@__riscv_\1', text)
    text = re.sub(r' immarg\b', '', text)
    return text


def main(argv):
    if not argv:
        print(__doc__)
        return 1
    for path in argv:
        with open(path) as f:
            text = f.read()
        with open(path, 'w') as f:
            f.write(clean_text(text))
        print(f"cleaned: {path}")
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
