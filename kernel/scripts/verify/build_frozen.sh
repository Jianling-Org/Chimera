#!/usr/bin/env bash
set -euo pipefail

readonly KERNEL_LOCALVERSION="-chimera-child-freeze"
readonly EXPECTED_RELEASE="6.18.3-prefer-a100-chimera-child-freeze"

if [[ $# -ne 1 ]]; then
    echo "usage: $0 /absolute/path/to/patched-linux-source" >&2
    exit 2
fi
[[ "$(uname -m)" == riscv64 ]] || { echo "Build on the K3 riscv64 board" >&2; exit 2; }
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TASK_KERNEL_SOURCE="$(cd "$1" && pwd)"
TASK_BUILD_OUT="${CHIMERA_KERNEL_EVIDENCE:-$HOME/.chimera/kernel-build/$(date +%Y%m%d-%H%M%S)}"
[[ ! -e "$TASK_BUILD_OUT" ]] || { echo "Preserve existing evidence: $TASK_BUILD_OUT" >&2; exit 2; }
mkdir -p "$TASK_BUILD_OUT"
trap 'TASK_BUILD_RC=$?; printf "%s\n" "$TASK_BUILD_RC" > "$TASK_BUILD_OUT/exit.rc"' EXIT
python3 -S "$SCRIPT_DIR/../check/source_identity.py" "$TASK_KERNEL_SOURCE" --expect frozen \
    > "$TASK_BUILD_OUT/source.json"
cd "$TASK_KERNEL_SOURCE"
[[ -f .config ]] || { echo "Prepare the frozen config in this clean source checkout first" >&2; exit 2; }
TASK_CONFIG_SHA="$(sha256sum .config | cut -d ' ' -f 1)"
[[ "$TASK_CONFIG_SHA" == 686032b6c65a9b13ff0baa83aad3a13154b586b02ac98984242c3d0b8cfe3f77 ]] || {
    echo "Config differs from frozen input; preserve and review it" >&2; exit 2;
}
cp .config "$TASK_BUILD_OUT/config.before"
uname -a > "$TASK_BUILD_OUT/build-host.txt"
gcc --version > "$TASK_BUILD_OUT/compiler.txt"
make_args=("LOCALVERSION=$KERNEL_LOCALVERSION")
make "${make_args[@]}" olddefconfig > "$TASK_BUILD_OUT/olddefconfig.log" 2>&1
cp .config "$TASK_BUILD_OUT/config.after"
# Reject a mismatched release before starting the expensive build.
make -s "${make_args[@]}" kernelrelease > "$TASK_BUILD_OUT/kernelrelease.before.txt"
grep -qx "$EXPECTED_RELEASE" "$TASK_BUILD_OUT/kernelrelease.before.txt"
printf '%q ' make -j8 "${make_args[@]}" Image modules > "$TASK_BUILD_OUT/build-command.txt"
printf '\n' >> "$TASK_BUILD_OUT/build-command.txt"
make -j8 "${make_args[@]}" Image modules > "$TASK_BUILD_OUT/build.log" 2>&1
make -s "${make_args[@]}" kernelrelease > "$TASK_BUILD_OUT/kernelrelease.txt"
grep -qx "$EXPECTED_RELEASE" "$TASK_BUILD_OUT/kernelrelease.txt"
sha256sum arch/riscv/boot/Image > "$TASK_BUILD_OUT/Image.sha256"
printf '0\n' > "$TASK_BUILD_OUT/build.rc"
echo "Build complete; evidence: $TASK_BUILD_OUT"
