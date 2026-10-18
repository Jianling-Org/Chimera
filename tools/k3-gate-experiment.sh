#!/usr/bin/env bash
# One-shot K3 command for the single-function gate experiment.
#
# It (1) hashes the exact toolchain inputs the run is about to consume into a
# toolchain evidence manifest, then (2) hands every input to the forensics
# driver's `gate-experiment` stage, which runs group A and group B
# sequentially and packages the whole evidence directory.
#
# Nothing here rewrites the production gate list, relinks GCC or changes a
# safety criterion: the experiment only ever writes into its own isolated
# results directory.
set -euo pipefail

CHIMERA="${CHIMERA:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
VENV="${VENV:-${VIRTUAL_ENV:?set VENV or activate a Python virtual environment}}"
PY="${PY:-$VENV/bin/python}"
RUN="${RUN:?set RUN to the staged GCC root}"
COLLECTION="${COLLECTION:?set COLLECTION to the collect result collection.json}"
GATE_DECISION="${GATE_DECISION:?set GATE_DECISION to the exact decision consumed by build-gate2}"
COMPILER="${COMPILER:?set COMPILER to the direct compiler binary of the reviewed compile entry}"
PLUGINS="${PLUGINS:?set PLUGINS to the space-separated plugin .so paths, in argv order}"
SOURCE="${SOURCE:?set SOURCE to the translation-unit source of the reviewed compile entry}"
ORIGINAL_OBJECT="${ORIGINAL_OBJECT:?set ORIGINAL_OBJECT to the collected object defining layout}"
RESOLUTION="${RESOLUTION:-}"
COMPILE_ENTRY_JSON="${COMPILE_ENTRY_JSON:-}"
COMPILE_DATABASE="${COMPILE_DATABASE:-}"
ENTRY_INDEX="${ENTRY_INDEX:-0}"

test -x "$PY" || { echo "STOP: missing Python $PY" >&2; exit 2; }
test -x "$CHIMERA/tools/k3-forensics-layout-codegen.sh" || {
  echo "STOP: missing the forensics driver under $CHIMERA/tools" >&2; exit 2; }

MANIFEST_DIR="$RUN/reports"
mkdir -p "$MANIFEST_DIR"
MANIFEST="$MANIFEST_DIR/gate-experiment-toolchain-$(date +%Y%m%d-%H%M%S).json"

export MANIFEST COMPILER PLUGINS SOURCE ORIGINAL_OBJECT GATE_DECISION COLLECTION
export RESOLUTION COMPILE_ENTRY_JSON
"$PY" - <<'PY'
"""Write the toolchain evidence manifest this experiment must reproduce."""
import hashlib
import json
import os
from pathlib import Path


def digest(path: str) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


env = os.environ
artifacts = {
    "compiler": {"path": env["COMPILER"], "sha256": digest(env["COMPILER"])},
    "source": {"path": env["SOURCE"], "sha256": digest(env["SOURCE"])},
    "original_object": {"path": env["ORIGINAL_OBJECT"],
                        "sha256": digest(env["ORIGINAL_OBJECT"])},
    "gate_decision": {"path": env["GATE_DECISION"], "sha256": digest(env["GATE_DECISION"])},
    "collection": {"path": env["COLLECTION"], "sha256": digest(env["COLLECTION"])},
}
for index, plugin in enumerate(env.get("PLUGINS", "").split()):
    artifacts[f"plugin:{index}"] = {"path": plugin, "sha256": digest(plugin)}
for key, name in (("RESOLUTION", "resolution"), ("COMPILE_ENTRY_JSON", "compile_entry")):
    if env.get(key):
        artifacts[name] = {"path": env[key], "sha256": digest(env[key])}
Path(env["MANIFEST"]).write_text(json.dumps(
    {"schema": "chimera-layout-gate-experiment-toolchain-v1", "artifacts": artifacts},
    indent=2), encoding="utf-8")
print("toolchain manifest:", env["MANIFEST"])
PY

export TOOLCHAIN_MANIFEST="$MANIFEST"
export COMPILE_DATABASE ENTRY_INDEX
exec "$CHIMERA/tools/k3-forensics-layout-codegen.sh" gate-experiment
