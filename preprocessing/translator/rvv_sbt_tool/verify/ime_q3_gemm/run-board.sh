#!/bin/sh
set -eu
environment() {
    uname -a || return $?
    gcc --version || return $?
    cat /proc/loadavg || return $?
    for path in /sys/devices/system/cpu/cpu8/cpufreq/scaling_governor /sys/devices/system/cpu/cpu8/cpufreq/scaling_cur_freq /sys/devices/system/cpu/cpu8/cpufreq/scaling_max_freq; do
        if test -r "$path"; then printf '%s ' "$path"; cat "$path" || return $?; fi
    done
}
printf 'environment-before\n' > run-stage.txt
if environment > environment-before.txt; then :; else
    status=$?
    printf '%s\n' "$status" > exit-status.txt
    exit "$status"
fi
if (
    printf 'setup\n' > run-stage.txt
    printf 0 > /proc/set_ai_thread || exit $?
    printf 'command\n' > run-stage.txt
    exec timeout 240s taskset -c 8 ./bench "$@"
) > results.jsonl 2> stderr.log; then
    status=0
else
    status=$?
fi
printf '%s\n' "$status" > exit-status.txt
if test "$status" -eq 0; then printf 'environment-after\n' > run-stage.txt; fi
if ! environment > environment-after.txt; then
    echo 'environment-after collection failed; see environment-after.txt' >&2
    test "$status" -ne 0 || status=1
    printf '%s\n' "$status" > exit-status.txt
fi
if test "$status" -eq 0; then printf 'complete\n' > run-stage.txt; fi
exit "$status"
