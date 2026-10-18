#!/bin/sh
set -eu
environment() {
    uname -a
    gcc --version
    cat /proc/loadavg
    for path in /sys/devices/system/cpu/cpu8/cpufreq/scaling_governor /sys/devices/system/cpu/cpu8/cpufreq/scaling_cur_freq /sys/devices/system/cpu/cpu8/cpufreq/scaling_max_freq; do
        if test -r "$path"; then printf '%s ' "$path"; cat "$path"; fi
    done
}
environment > environment-before.txt
if (printf 0 > /proc/set_ai_thread; exec timeout 240s taskset -c 8 ./bench "$@") > results.jsonl 2> stderr.log; then
    status=0
else
    status=$?
fi
environment > environment-after.txt
printf '%s\n' "$status" > exit-status.txt
exit "$status"
