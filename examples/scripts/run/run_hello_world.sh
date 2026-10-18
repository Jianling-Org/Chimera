#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../build/_common.sh"
WORKSPACE="${CHIMERA_EXAMPLE_WORKSPACE:-hello_world}"
BINARY="${CHIMERA_EXAMPLE_ELF:-${CHIMERA_EXAMPLE_ARTIFACT_ROOT:-$HOME/.chimera/examples/hello_world}/hello-world}"
RUN_LOG="$(mktemp)"
RUN_PID=""
WATCHDOG_PID=""
cleanup() {
    if [[ -n "$WATCHDOG_PID" ]]; then
        kill "$WATCHDOG_PID" 2>/dev/null || true
        wait "$WATCHDOG_PID" 2>/dev/null || true
    fi
    if [[ -n "$RUN_PID" ]] && kill -0 "$RUN_PID" 2>/dev/null; then
        kill "$RUN_PID" 2>/dev/null || true
        wait "$RUN_PID" 2>/dev/null || true
    fi
    rm -f "$RUN_LOG"
}
trap cleanup EXIT

"$CHIMERA_USER" verify --workspace "$WORKSPACE" --input "$BINARY"
"$CHIMERA_USER" register --workspace "$WORKSPACE" --input "$BINARY"
"$CHIMERA_USER" --debug run --workspace "$WORKSPACE" --input "$BINARY" > >(tee "$RUN_LOG") 2>&1 &
RUN_PID=$!
# Bound the demo even when a target runtime loses its migration control path.
( sleep 30; if kill -0 "$RUN_PID" 2>/dev/null; then kill "$RUN_PID" 2>/dev/null || true; fi ) &
WATCHDOG_PID=$!
for _ in $(seq 1 100); do
    grep -q 'CHIMERA_HELLO_READY=1' "$RUN_LOG" && grep -q 'CHIMERA_HELLO_ACTIVE=1' "$RUN_LOG" && break
    kill -0 "$RUN_PID" 2>/dev/null || { wait "$RUN_PID"; exit 1; }
    sleep 0.1
done
grep -q 'CHIMERA_HELLO_READY=1' "$RUN_LOG" || { echo "Hello World did not become ready" >&2; exit 1; }
grep -q 'CHIMERA_HELLO_ACTIVE=1' "$RUN_LOG" || { echo "Hello World did not enter vector compute" >&2; exit 1; }
grep -q 'CHIMERA_HELLO_VECTOR=rvv' "$RUN_LOG" || { echo "Hello World did not execute vector code" >&2; exit 1; }
"$CHIMERA_USER" migrate --workspace "$WORKSPACE" --parent-thread "$RUN_PID" --migration-count 1 --direction 1024-to-256
if wait "$RUN_PID"; then
    RUN_STATUS=0
else
    RUN_STATUS=$?
fi
kill "$WATCHDOG_PID" 2>/dev/null || true
wait "$WATCHDOG_PID" 2>/dev/null || true
WATCHDOG_PID=""
if [[ "$RUN_STATUS" -ne 0 ]]; then
    exit "$RUN_STATUS"
fi
grep -q 'CHIMERA_HELLO_CHECKSUM=' "$RUN_LOG"
grep -q 'CHIMERA_HELLO_REFERENCE=' "$RUN_LOG"
grep -q 'action=rewrite' "$RUN_LOG" || { echo "Hello World migration emitted no address-rewrite event" >&2; exit 1; }
