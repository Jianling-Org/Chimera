#!/bin/bash
# Export exactly the function bodies the origin proofs asked for.
#
# The check writes every callee whose body a proof needed but could not read
# into ``missing_internal_targets`` (reason ``missing-callee-body`` for an
# internal target that was simply not part of the analysed program).  This
# script turns that list into an evidence package in the same shape as the
# fixtures: ``index.txt``, ``function-<n>.txt``, ``elf.sha256``.
#
# It never re-runs a full check: the addresses come from the report, the bodies
# come from the same ELF.
#
# Usage:
#   tools/k3-fetch-origin-targets.sh <inheritance-report.json> <elf> [outdir] [objdump]
#
#   tools/k3-fetch-origin-targets.sh \
#     "$OUT/xgcc.inheritance.json" "$RUN/build-gate2/gcc/xgcc" "$OUT/origin-bodies"

set -euo pipefail

REPORT=${1:?usage: $0 <inheritance-report.json> <elf> [outdir] [objdump]}
ELF=${2:?usage: $0 <inheritance-report.json> <elf> [outdir] [objdump]}
OUTDIR=${3:-$(dirname "$REPORT")/origin-bodies}
OBJDUMP=${4:-objdump}

test -f "$REPORT"
test -f "$ELF"
mkdir -p "$OUTDIR"

# The addresses come from the report, not from prose: classification and this
# script read the same structured field.
python3 - "$REPORT" "$OUTDIR" <<'PY'
import json, sys, pathlib

report, outdir = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
document = json.loads(report.read_text(encoding="utf-8"))
targets = [
    entry for entry in document.get("missing_internal_targets", [])
    if entry.get("reason") == "missing-callee-body"
]
entries = []
for index, entry in enumerate(targets):
    entries.append({
        "index": index,
        "address": entry["address"],
        "name": entry.get("name") or entry["address"],
        "reason": entry["reason"],
        "file": f"function-{index}.txt",
    })
# Written with explicit LF endings: the report may be produced on any
# platform and a stray CR must not reach the arithmetic below.
with (outdir / "pending.txt").open("w", encoding="utf-8", newline="\n") as handle:
    for entry in entries:
        handle.write(
            f"{entry['index']}\t{entry['name']}\t{entry['address']}\n"
        )
print("\n".join(entry["address"] for entry in entries))
PY

# The pending list drives the dump loop: one body per missing target.
while IFS=$'\t' read -r index name address; do
  address=${address%$'\r'}
  [ -n "${address:-}" ] || continue
  start=$((address))
  stop=$((address + 0x1000))
  {
    echo "$name ($address)"
    "$OBJDUMP" -d --start-address="$start" --stop-address="$stop" "$ELF"
  } > "$OUTDIR/function-$index.txt"
done < "$OUTDIR/pending.txt"

cp "$OUTDIR/pending.txt" "$OUTDIR/index.txt"
sha256sum "$ELF" > "$OUTDIR/elf.sha256"

echo "wrote $(wc -l < "$OUTDIR/index.txt") function body(ies) to $OUTDIR"
echo "elf hash: $(cut -d' ' -f1 "$OUTDIR/elf.sha256")"
