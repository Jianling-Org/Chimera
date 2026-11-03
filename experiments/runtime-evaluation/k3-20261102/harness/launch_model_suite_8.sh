set -eu
number="$1"
case "$number" in 41|42) ;; *) exit 2 ;; esac
P=/root/chimera-runtime-retest-20261031
if systemctl list-units --state=active,activating --no-legend --plain 'chimera*' | grep -q .; then
    echo ACTIVE_CHIMERA_UNIT_EXISTS
    exit 91
fi
if test -e "$P/model${number}-runtime-ppl2pct-v5-attempt1"; then exit 90; fi
systemd-run --unit="chimera-model${number}-runtime-ppl2pct-v5-controller-1" --service-type=exec \
    --property=MemoryMax=1G --property=MemorySwapMax=0 --property=RuntimeMaxSec=5h \
    --property=OOMPolicy=stop --property=KillMode=control-group \
    --property="ExecStopPost=/usr/bin/python3 -B $P/model_runtime_controller_7.py --resources $number" \
    /usr/bin/time -v -o "$P/model${number}-runtime-ppl2pct-v5-controller-1.time.txt" \
    /usr/bin/python3 -B "$P/model_runtime_controller_7.py" "$number"
