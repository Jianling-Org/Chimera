#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
source "$SCRIPT_DIR/_common.sh"
PROFILE="${CHIMERA_HELLO_PROFILE:-$REPO_ROOT/examples/platforms/k3/hello-world.toml}"
ROOT="${CHIMERA_EXAMPLE_ARTIFACT_ROOT:-$HOME/.chimera/examples/hello_world}"
ELF="$ROOT/hello-world"
CC_BIN="${CHIMERA_HELLO_CC:-${CC:-cc}}"
CFLAGS=( ${CHIMERA_HELLO_CFLAGS:--march=rv64gcv -mabi=lp64d} )
mkdir -p "$ROOT"
"$CC_BIN" -O2 -g -std=c11 -pthread "${CFLAGS[@]}" "$REPO_ROOT/examples/applications/hello-world/hello_world.c" -o "$ELF"
"$CHIMERA_PKG" check-elf --profile "$PROFILE" --input "$ELF" --strict
# --debug makes the generated Runtime emit the address-rewrite event that the
# demo checks after migration.
"$CHIMERA_PKG" --debug prepare --profile "$PROFILE" --input "$ELF" --workspace hello_world
echo "hello_world_elf=$ELF"
