#!/usr/bin/env bash
# Read-only field forensics for the layout / metadata-mode divergence.
#
# Collects, for BOTH build-stack/gcc/xgcc and build-gate2/gcc/xgcc:
#   * SHA-256 of each ELF
#   * full section tables
#   * raw .chimera.stackobj_map records and their decoded (LinkedVA, SOID) pairs
#   * complete function disassembly of the layout constructor (both stages)
#   * the two-stage wrappers, consumed decisions and build logs
#   * every census file under $RUN, with hashes, marked UNBOUND
#
# It also separates four facts that must never be substituted for one another:
#   A. plugin-requested    -- the build asked for the stackobject plugin
#   B. plugin-participated -- >=1 compile line loaded ChimeraStackObject
#                             (NOT "every linked object was covered")
#   C. metadata-retained   -- the linked ELF still carries .chimera.stackobj_map
#   D. link-coverage       -- every relevant linked object was plugin-built
# A/B/D are three-valued (yes | none-found-in-log | insufficient-evidence);
# 0 matching lines is never reported as a bare "no".
#
# It exports the FORWARD propagation path of the smallest affected call site
# (layout's active calls -> callees -> the site's host).  The reverse edge
# ("does the host call layout") answers a different question and is not used.
#
# Nothing here writes to an ELF, a decision, a check credential or a safety
# criterion.  Exit 0 only means the evidence was collected.
#
# Usage (on the machine that holds $RUN):
#   RUN=/absolute/path/to/staged-gcc \
#   bash tools/k3-forensics-layout-metadata.sh
#
# Optional: INHERITANCE=/path/xgcc.inheritance.json
#   Supplies the analysis result whose seed_edges name the object-active
#   calls.  Without it the propagation trace is graded `callgraph-path-only`
#   and G2 is NOT reported as filled.
set -euo pipefail

RUN="${RUN:?set RUN to the staged rebuild root}"
CHIMERA="${CHIMERA:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
VENV="${VENV:-${VIRTUAL_ENV:?set VENV or activate a Python virtual environment}}"
PY="${PY:-$VENV/bin/python}"
LAYOUT_SYMBOL="${LAYOUT_SYMBOL:-_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info}"

XGCC_STACK="$RUN/build-stack/gcc/xgcc"
XGCC_GATE2="$RUN/build-gate2/gcc/xgcc"
test -r "$XGCC_STACK" || { echo "STOP: unreadable $XGCC_STACK"; exit 1; }
test -r "$XGCC_GATE2" || { echo "STOP: unreadable $XGCC_GATE2"; exit 1; }
test -x "$PY" || { echo "STOP: unreadable interpreter $PY"; exit 1; }
command -v objdump >/dev/null
command -v readelf >/dev/null

mkdir -p "$RUN/reports"
OUT=$(mktemp -d "$RUN/reports/layout-metadata-forensics-$(date +%Y%m%d-%H%M%S)-XXXXXX")
printf '%s\n' "$OUT" > "$RUN/last-layout-metadata-forensics.txt"
echo "Results: $OUT"
trap 'rc=$?; echo "Script exit=$rc; results=$OUT (read-only forensics, not a safety verdict)"' EXIT

# ---------------------------------------------------------------- identity
{
  echo "# input identity (read-only)"
  echo "run=$RUN"
  echo "collected_at=$(date -Is)"
  echo "chimera=$CHIMERA"
  echo "venv=$VENV"
  echo "layout_symbol=$LAYOUT_SYMBOL"
  echo
  echo "# SHA-256 of the two xgcc files"
  sha256sum "$XGCC_STACK" "$XGCC_GATE2"
} > "$OUT/identity.txt"
sha256sum "$XGCC_STACK" "$XGCC_GATE2" > "$OUT/inputs.sha256"

# ------------------------------------------------------- three plugin facts
# Three facts that must never be substituted for one another, each reported on
# a three-valued scale:
#   A. plugin-requested        -- the build asked for the stackobject plugin
#   B. plugin-participated     -- at least one compile line loaded the plugin
#      (this is NOT "every linked object was covered"; see D)
#   C. metadata-retained       -- the linked ELF still carries stackobj_map
#   D. link-coverage           -- every relevant linked object was plugin-built
#
# 0 matching lines in a log is NOT proof of non-participation: the log may be
# truncated, the compile lines may use another spelling, or the objects may
# come from a second toolchain invocation.  Report "none-found-in-log", never
# a bare "no".
{
  echo "# Four distinct facts.  None of them substitutes for another."
  echo "# A plugin-requested    -- the wrapper/build enabled stackobject"
  echo "# B plugin-participated -- >=1 compile line loaded ChimeraStackObject"
  echo "#                         (NOT 'every linked object was covered')"
  echo "# C metadata-retained   -- the linked ELF still carries stackobj_map"
  echo "# D link-coverage       -- every relevant linked object was plugin-built"
  echo "#"
  echo "# Scale for A/B/D: yes | none-found-in-log | insufficient-evidence"
  echo "# 0 matches in a log is 'none-found-in-log', never a bare 'no'."
  echo
  for label in stack gate2; do
    case "$label" in
      stack)  log="$RUN/logs/stack-build.log";  elf="$XGCC_STACK";  stage=build-stack ;;
      gate2)  log="$RUN/logs/gate2-build.log";  elf="$XGCC_GATE2";  stage=build-gate2 ;;
    esac
    echo "## $stage"
    if test -f "$log"; then
      requested=$(grep -c -- '--fpass-plugin=.*ChimeraStackObject\|CHIMERA_ENABLE_STACKOBJECT\|plugins stackobject' "$log" || true)
      participated=$(grep -c -- 'fpass-plugin=.*ChimeraStackObject' "$log" || true)
      if [ "$requested" -gt 0 ]; then a=yes; else a=none-found-in-log; fi
      if [ "$participated" -gt 0 ]; then b=yes; else b=none-found-in-log; fi
      echo "plugin_requested=$a (matching_lines=$requested)"
      echo "plugin_participated=$b (matching_lines=$participated)"
      echo "plugin_participated_note=at-least-one-line, NOT per-TU coverage"
    else
      echo "plugin_requested=insufficient-evidence (no $log)"
      echo "plugin_participated=insufficient-evidence (no $log)"
      echo "plugin_participated_note=no log to inspect"
    fi
    if readelf -SW "$elf" | grep -qF '.chimera.stackobj_map'; then
      echo "metadata_retained=yes"
    else
      echo "metadata_retained=no"
    fi
    # D cannot be answered from a compile-line grep alone: it needs an
    # inventory of the objects that were linked into this ELF, each matched
    # against the set of plugin-enabled compile lines.  Until that inventory
    # exists the only honest answer is insufficient-evidence.
    echo "link_coverage=insufficient-evidence (no linked-object inventory)"
    echo "link_coverage_note=needs: every linked .o matched against plugin-enabled compile lines"
    echo
  done
} > "$OUT/plugin-facts.txt"

# ----------------------------------------------------------- section tables
for label in stack gate2; do
  case "$label" in
    stack) elf="$XGCC_STACK" ;;
    gate2) elf="$XGCC_GATE2" ;;
  esac
  readelf -SW "$elf" > "$OUT/$label.sections.txt"
  readelf -lW "$elf" > "$OUT/$label.program-headers.txt"
done

# ------------------------------------- stack-object raw records + decoding
"$PY" -I - "$XGCC_STACK" "$XGCC_GATE2" "$OUT" <<'PY' | tee "$OUT/stackobj-records.log"
import hashlib, json, struct, sys
from pathlib import Path

stack_elf, gate2_elf, out = map(Path, sys.argv[1:4])
RECORD = struct.Struct("<QI")

def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def section_bytes(path: Path, name: str):
    from elftools.elf.elffile import ELFFile
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        section = elf.get_section_by_name(name)
        if section is None:
            return None
        return bytes(section.data())

report = {}
for stage, path in (("stack", stack_elf), ("gate2", gate2_elf)):
    blob = section_bytes(path, ".chimera.stackobj_map")
    fp_blob = section_bytes(path, ".chimera.function_pointer")
    entry = {
        "sha256": sha256(path),
        "stackobj_map_present": blob is not None,
        "stackobj_map_size": None if blob is None else len(blob),
        "function_pointer_present": fp_blob is not None,
        "function_pointer_size": None if fp_blob is None else len(fp_blob),
        "records": [],
    }
    if blob is not None:
        if len(blob) % RECORD.size:
            entry["decode_error"] = f"size {len(blob)} is not a multiple of {RECORD.size}"
        else:
            for address, object_id in RECORD.iter_unpack(blob):
                entry["records"].append(
                    {"linked_va": hex(address), "soid": object_id}
                )
    report[stage] = entry
    present = "present" if blob is not None else "ABSENT"
    print(f"{stage}: .chimera.stackobj_map {present} "
          f"size={entry['stackobj_map_size']} records={len(entry['records'])}")

(out / "stackobj-records.json").write_text(
    json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
)
print("wrote", out / "stackobj-records.json")
PY

# ------------------------------------------- layout disassembly (both)
for label in stack gate2; do
  case "$label" in
    stack) elf="$XGCC_STACK" ;;
    gate2) elf="$XGCC_GATE2" ;;
  esac
  objdump -d --disassemble="$LAYOUT_SYMBOL" "$elf" \
    > "$OUT/$label.layout.dump.txt"
  wc -l "$OUT/$label.layout.dump.txt" >> "$OUT/layout-dump-sizes.txt"
done

# ------------------------------- wrappers, decisions, build logs (hash only)
{
  echo "# two-stage wrappers / consumed decisions / build logs (paths + hashes)"
  echo "# files are NOT copied; only their identity is recorded"
  echo
  for f in \
      "$RUN"/logs/*.log \
      "$RUN"/decisions/*.json \
      "$RUN"/reports/stackobj-addr-fix-*/stack-and-gate.addrfix.json \
      "$RUN"/reports/stackobj-addr-fix-*/stack-only*.json \
      "$RUN"/*.decision.json \
      "$RUN"/profile.used.toml
  do
    test -f "$f" || continue
    printf '%s  %s\n' "$(sha256sum "$f" | cut -d' ' -f1)" "$f"
  done
  echo
  echo "# decision-inventory (declared, not derived)"
  if test -d "$RUN/decisions"; then
    ls -la "$RUN/decisions"
  else
    echo "(no $RUN/decisions directory)"
  fi
} > "$OUT/build-artifacts.sha256"

# ------------------------------------------------ census files, marked UNBOUND
{
  echo "# census files found under \$RUN"
  echo "# UNBOUND means: not proven to belong to this stage / consumed decision /"
  echo "# compile unit / toolchain identity.  An unbound census neither proves"
  echo "# nor refutes the gate.  Do NOT treat this listing as evidence."
  echo
  found=0
  while IFS= read -r f; do
    found=$((found + 1))
    printf 'UNBOUND  %s  %s  %s\n' \
      "$(sha256sum "$f" | cut -d' ' -f1)" "$(wc -l < "$f")" "$f"
  done < <(find "$RUN" -type f -name '*implicit_vector_census.tsv' 2>/dev/null | sort)
  if [ "$found" -eq 0 ]; then
    echo "(none found)"
  fi
  echo
  echo "# evidence manifests (if any)"
  find "$RUN" -type f \( -name '*evidence*manifest*' -o -name '*manifest*evidence*' \) 2>/dev/null | sort
} > "$OUT/census-inventory.txt"

# ---------------------------------- trace the smallest affected call site
# The gate-2 audit listed 67 affected sites for layout's irreducible-degradation
# source; the smallest is the one this block traces.
#
# DIRECTION MATTERS.  The affected site is NOT a caller of layout.  The source
# propagates FORWARD: an active call inside layout hands the live object to a
# callee, which hands it on, and the affected site is an unresolved call inside
# one of those descendants.  The required export is therefore
#
#   layout 活跃调用 → 若干被调函数 → 受影响站点宿主
#
# searching the host's body for a call TO layout would be the reverse edge and
# answers a different (wrong) question.
#
# GRADE MATTERS.  Walking every call is call-graph *reachability*, not
# propagation.  A hop only carries the source if the object is live at that
# call site.  Without an analysis result that names the object-active seed
# calls this block can only answer `callgraph-path-only` and must NOT close
# the propagation-trace gap.
#
# TARGET RESOLUTION MATTERS.  Functions are identified by ADDRESS, never by
# name substring.  A call target must be an **exact function entry** (the
# production `_CallTargetResolver` rule): `<foobar>` is not `foo`, `<foo+0x20>`
# is an in-function position, and `0x9000 <external@plt>` is NOT `host` just
# because `host` starts at `0x8000`.  Unknown targets, `@plt` stubs and
# out-of-range addresses keep the gap and never become edges.  Call/jump
# classification follows the CFG rule (`jal`/`jalr` with a non-zero link
# register, or `call`); `j`/`tail`/`jal x0` are not edges.
#
# EDGE GRADE MATTERS.  Edges inferred from objdump are *suspected*
# (`resolved_by=disassembly`) and cannot on their own authorise
# `analysis-trace`; only production `_CallTargetResolver` edges can.
SMALLEST_SITE="${SMALLEST_SITE:-0x3f176}"

# Strong + weak propagation trace.  The Python driver is the testable entry:
# it parses the Program ONCE, logs only bounded scalars (never expands a
# Function/Program/edge graph), emits flushed stage events with KiB memory
# counters, and releases its references to the CFG before the weak path.
# /usr/bin/time -v records the overall peak and exit status of this one
# Python process.  -I keeps the isolated import path; -u flushes stage logs.
# The driver itself owns $OUT/smallest-site-trace.log (and its JSON); the
# shell must never tee into that path again.
source "$CHIMERA/tools/k3-record-exit-status.sh"
if command -v /usr/bin/time >/dev/null 2>&1; then
  TIME_WRAP=(/usr/bin/time -v -o "$OUT/smallest-site-trace.time.txt")
else
  TIME_WRAP=()
  echo "WARNING: /usr/bin/time not found; overall peak not recorded" \
    | tee "$OUT/smallest-site-trace.time.txt"
fi

run_and_record_exit "$OUT/smallest-site-trace.exit.txt" "${TIME_WRAP[@]}" "$PY" -I -u -c "
import sys
from pathlib import Path
chimera_root = Path(r'''$CHIMERA''')
sys.path.insert(0, str(chimera_root))
sys.path.insert(0, str(chimera_root / 'tests'))
sys.path.insert(0, str(chimera_root / 'cli'))
from layout_forensics_driver import run_trace
run_trace(
    elf=Path(r'''$XGCC_GATE2'''),
    out=Path(r'''$OUT'''),
    site=int(r'''$SMALLEST_SITE''', 16),
    layout_symbol=r'''$LAYOUT_SYMBOL''',
    inheritance=(r'''${INHERITANCE:-}''' or None),
)
"

# ------------------------------------------------------------- summary
{
  echo "layout-metadata forensics (READ-ONLY)"
  echo "results=$OUT"
  echo
  echo "## plugin / coverage facts (three-valued; 0 matches is not 'no')"
  grep -E 'plugin_requested=|plugin_participated=|metadata_retained=|link_coverage=' \
    "$OUT/plugin-facts.txt" || true
  echo
  echo "## stackobj_map"
  grep -E 'stackobj_map' "$OUT/stackobj-records.log" || true
  echo
  echo "## forward propagation trace (layout -> callees -> site host)"
  grep -E 'stage=|grade:|is_propagation_evidence|g2_filled|path_grade|site |program functions=' \
    "$OUT/smallest-site-trace.log" || true
  echo
  echo "## census (UNBOUND unless a manifest binds them)"
  head -n 8 "$OUT/census-inventory.txt"
  echo
  echo "NOT collected here, still open:"
  echo "  G2 -- forward propagation trace.  Graded 'callgraph-path-only' unless"
  echo "        INHERITANCE named an analysis result with object-active seed"
  echo "        calls.  Only 'analysis-trace' is propagation evidence."
  echo "  G6 -- plugin-side classification of layout's two irreducible-loop"
  echo "        vs2r.v stores (0x50d6c / 0x50fb8).  Must check BOTH paths:"
  echo "        IR (StackObjectPass CallBase / inline asm, incl. the"
  echo "        MultipleLocations / UnknownProvenance / unscanned cases) AND"
  echo "        backend (patch 0004/0005 storeRegToStackSlot/"
  echo "        loadRegFromStackSlot RVV spill/reload, which can emit VS1R_V)."
  echo "        Absence from .chimera.stackobj_map is NOT proof of irrelevance,"
  echo "        and the opcode name alone does not say which path produced it."
  echo
  echo "This run collected evidence only.  It did not modify any ELF, decision,"
  echo "check credential or safety criterion, and it is not a safety verdict."
} | tee "$OUT/summary.txt"

echo "trace_python_exit_status=$TRACE_EXIT_STATUS"
exit "$TRACE_EXIT_STATUS"
