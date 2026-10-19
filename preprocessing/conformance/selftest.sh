#!/usr/bin/env bash
# ==============================================================================
# vlen-escape self-test: run the bundled hello_make example end to end and
# assert the expected escape record (main.c:6, GLOBAL store to g_vl).
# ==============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1; pwd -P)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

cp -r "$SCRIPT_DIR/examples/hello_make" "$TMP/hello_make"

bash "$SCRIPT_DIR/run.sh" "$TMP/hello_make" -o "$TMP/out" -- make -B || {
    echo "SELFTEST FAIL: run.sh"; exit 1; }

python3 - "$TMP/out/escapes.jsonl" <<'PYEOF'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
assert len(rows) == 1, f"expected 1 escape, got {len(rows)}"
e = rows[0]
assert e["function"] == "main" and e["kind"] == "GLOBAL", e
assert e["target"] == "GLOBAL::g_vl", e
assert e["file"].endswith("main.c") and e["line"] == 6, e
print("escape record:", json.dumps(e))
print("SELFTEST PASS")
PYEOF
