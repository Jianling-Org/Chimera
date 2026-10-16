#!/usr/bin/env bash
set -euo pipefail

# Repeat the selected llama.cpp example scenarios and average the metrics emitted
# by llama-perplexity.
#
# Usage examples:
#
#   # Run all five scenarios (default)
#   ./run_llamacpp_benchmark.sh
#
#   # Run all five scenarios for 10 rounds
#   ./run_llamacpp_benchmark.sh --runs 10
#
#   # Run only one scenario
#   ./run_llamacpp_benchmark.sh --runs 10 --scenario 256-pure
#
#   # Run multiple selected scenarios
#   ./run_llamacpp_benchmark.sh \
#       --runs 10 \
#       --scenario 256-pure \
#       --scenario 1024-pure
#
# Available scenarios:
#   256-pure
#   1024-pure
#   256-to-1024
#   1024-to-256
#   run_llamacpp_scheduler
#
# The migrated and scheduler scenarios inherit MODEL, PROMPT_FILE,
# MIGRATION_COUNT, MIGRATE_DELAY, MIN_THREADS and THREAD_WAIT_TIMEOUT unchanged.

export LC_ALL=C

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../../.." && pwd -P)"
LLAMA_APP_ROOT="$REPO_ROOT/examples/applications/llama-cpp"
LLAMA_SOURCE="$LLAMA_APP_ROOT/llama.cpp"
source "$SCRIPT_DIR/_common.sh"
BINARY="$(chimera_example_artifact_root)/main/llama-perplexity-bidirectional"
MODEL="$(chimera_resolve_model)" || exit 1
PROMPT_FILE="${PROMPT_FILE:-$LLAMA_APP_ROOT/prompt/file.txt}"
THREAD_CONTROL="${CHIMERA_BENCHMARK_AI_THREAD_CONTROL:-/proc/set_ai_thread}"

ALL_SCENARIOS=(
    "256-pure"
    "1024-pure"
    "256-to-1024"
    "1024-to-256"
    "run_llamacpp_scheduler"
)

# If no --scenario is supplied, this will be populated with ALL_SCENARIOS
# after argument parsing.
SCENARIOS=()
SCENARIO_FILTER_SET=0

usage() {
    cat >&2 <<EOF
usage: $0 [--runs N] [--scenario NAME ...]

Options:
  --runs N
      Number of benchmark rounds.
      Default: BENCHMARK_RUNS or 50.

  --scenario NAME
      Run only the specified scenario.
      May be specified multiple times.
      If omitted, all five scenarios are run.

Available scenarios:
  256-pure
  1024-pure
  256-to-1024
  1024-to-256
  run_llamacpp_scheduler

Examples:
  $0 --runs 10
  $0 --runs 10 --scenario 256-pure
  $0 --runs 10 --scenario 256-pure --scenario 1024-pure
EOF
}

die_usage() {
    echo "ERROR: $*" >&2
    usage
    exit 2
}

add_scenario() {
    local scenario="$1"
    local existing

    case "$scenario" in
        256-pure|1024-pure|256-to-1024|1024-to-256|run_llamacpp_scheduler)
            ;;
        *)
            die_usage "unknown scenario: $scenario"
            ;;
    esac

    if ((SCENARIO_FILTER_SET == 0)); then
        SCENARIOS=()
        SCENARIO_FILTER_SET=1
    fi

    # Ignore duplicate --scenario arguments.
    for existing in "${SCENARIOS[@]}"; do
        if [[ "$existing" == "$scenario" ]]; then
            return 0
        fi
    done

    SCENARIOS+=("$scenario")
}

scenario_is_selected() {
    local wanted="$1"
    local scenario

    for scenario in "${SCENARIOS[@]}"; do
        if [[ "$scenario" == "$wanted" ]]; then
            return 0
        fi
    done

    return 1
}

RUNS="${BENCHMARK_RUNS:-50}"

while (($# > 0)); do
    case "$1" in
        --runs)
            (($# >= 2)) || die_usage "--runs requires a positive integer"
            [[ "$2" =~ ^[1-9][0-9]*$ ]] || \
                die_usage "--runs must be a positive integer (got '$2')"
            RUNS="$2"
            shift 2
            ;;

        --runs=*)
            value="${1#--runs=}"
            [[ "$value" =~ ^[1-9][0-9]*$ ]] || \
                die_usage "--runs must be a positive integer (got '$value')"
            RUNS="$value"
            shift
            ;;

        --scenario)
            (($# >= 2)) || die_usage "--scenario requires a scenario name"
            add_scenario "$2"
            shift 2
            ;;

        --scenario=*)
            value="${1#--scenario=}"
            [[ -n "$value" ]] || die_usage "--scenario requires a scenario name"
            add_scenario "$value"
            shift
            ;;

        --)
            shift
            (($# == 0)) || die_usage "unexpected arguments after --: $*"
            ;;

        *)
            die_usage "unknown argument: $1"
            ;;
    esac
done

if [[ ! "$RUNS" =~ ^[1-9][0-9]*$ ]]; then
    die_usage "BENCHMARK_RUNS must be a positive integer (got '$RUNS')"
fi

# No --scenario means run all scenarios.
if ((SCENARIO_FILTER_SET == 0)); then
    SCENARIOS=("${ALL_SCENARIOS[@]}")
fi

SCENARIO_COUNT="${#SCENARIOS[@]}"

for tool in bash awk grep sed tail date mkdir rm kill; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "ERROR: required shell tool is missing: $tool" >&2
        exit 2
    }
done

for path in "$BINARY" "$MODEL" "$PROMPT_FILE"; do
    [[ -f "$path" ]] || {
        echo "ERROR: required benchmark input is missing: $path" >&2
        echo "       请先在部署机 prepare 并交付 .workspace 包" >&2
        exit 2
    }
done

[[ -x "$BINARY" ]] || {
    echo "ERROR: final llama-perplexity ELF is not executable: $BINARY" >&2
    echo "       请先在部署机 prepare 并交付 .workspace 包" >&2
    exit 2
}

# Only validate scenario scripts that are actually selected.
for scenario in "${SCENARIOS[@]}"; do
    scenario_script=""

    case "$scenario" in
        256-to-1024)
            scenario_script="$SCRIPT_DIR/run_llamacpp_256_to_1024.sh"
            ;;
        1024-to-256)
            scenario_script="$SCRIPT_DIR/run_llamacpp_1024_to_256.sh"
            ;;
        run_llamacpp_scheduler)
            scenario_script="$SCRIPT_DIR/run_llamacpp_scheduler.sh"
            ;;
    esac

    if [[ -n "$scenario_script" && ! -f "$scenario_script" ]]; then
        echo "ERROR: benchmark scenario script is missing: $scenario_script" >&2
        exit 2
    fi
done

# THREAD_CONTROL is only needed by 1024-pure.
if scenario_is_selected "1024-pure"; then
    [[ -e "$THREAD_CONTROL" && -w "$THREAD_CONTROL" ]] || {
        echo "ERROR: 1024-pure thread-control file is missing or not writable: $THREAD_CONTROL" >&2
        echo "       set CHIMERA_BENCHMARK_AI_THREAD_CONTROL for an isolated test control file" >&2
        exit 2
    }
fi

OUTPUT_DIR="${BENCHMARK_OUTPUT_DIR:-$HOME/.chimera/data/benchmarks/llamacpp-$(date -u +%Y%m%dT%H%M%SZ)-$$}"

if ! mkdir -p -- "$OUTPUT_DIR"; then
    echo "ERROR: cannot create benchmark output directory: $OUTPUT_DIR" >&2
    exit 2
fi

if ! OUTPUT_DIR="$(cd -- "$OUTPUT_DIR" && pwd -P)"; then
    echo "ERROR: benchmark output directory is not accessible: $OUTPUT_DIR" >&2
    exit 2
fi

SAMPLES="$OUTPUT_DIR/samples.tsv"
SUMMARY="$OUTPUT_DIR/summary.tsv"
LOG_DIR="$OUTPUT_DIR/logs"

if [[ -e "$SAMPLES" || -L "$SAMPLES" ]]; then
    echo "ERROR: refusing to overwrite existing benchmark samples: $SAMPLES" >&2
    exit 2
fi

if ! mkdir -p -- "$LOG_DIR"; then
    echo "ERROR: cannot create benchmark log directory: $LOG_DIR" >&2
    exit 2
fi

if ! printf 'round\tposition\tscenario\tstatus\texit_code\tseconds_per_pass\tppl\tlog_path\n' > "$SAMPLES"; then
    echo "ERROR: cannot write benchmark samples: $SAMPLES" >&2
    exit 2
fi

echo "benchmark configuration:"
echo "  rounds:    $RUNS"
echo "  scenarios: ${SCENARIOS[*]}"
echo "  output:    $OUTPUT_DIR"

CURRENT_PID=""

benchmark_signal() {
    local status="$1"

    if [[ -n "$CURRENT_PID" ]] && kill -0 "$CURRENT_PID" 2>/dev/null; then
        kill "$CURRENT_PID" 2>/dev/null || true
        wait "$CURRENT_PID" 2>/dev/null || true
    fi

    CURRENT_PID=""

    # Keep the current log and samples.tsv so an interrupted run is auditable.
    exit "$status"
}

trap 'benchmark_signal 130' INT
trap 'benchmark_signal 143' TERM

run_pure() {
    exec "$BINARY" -m "$MODEL" -f "$PROMPT_FILE"
}

run_pure_1024() {
    # This function runs in the sample background subshell. BASHPID identifies
    # that subprocess, without pinning the benchmark parent or later samples.
    printf '%s\n' "$BASHPID" > "$THREAD_CONTROL"
    exec "$BINARY" -m "$MODEL" -f "$PROMPT_FILE"
}

run_scenario() {
    case "$1" in
        256-pure)
            run_pure
            ;;

        1024-pure)
            run_pure_1024
            ;;

        256-to-1024)
            exec bash "$SCRIPT_DIR/run_llamacpp_256_to_1024.sh"
            ;;

        1024-to-256)
            exec bash "$SCRIPT_DIR/run_llamacpp_1024_to_256.sh"
            ;;

        run_llamacpp_scheduler)
            exec bash "$SCRIPT_DIR/run_llamacpp_scheduler.sh"
            ;;

        *)
            echo "ERROR: internal unknown benchmark scenario: $1" >&2
            return 2
            ;;
    esac
}

FAILED_TOTAL=0

run_sample() {
    local round="$1"
    local position="$2"
    local scenario="$3"

    local safe_name="${scenario//[^A-Za-z0-9_.-]/_}"
    local log="$LOG_DIR/round-${round}-position-${position}-${safe_name}.log"
    local exit_code=0
    local status
    local seconds
    local ppl
    local log_field

    run_scenario "$scenario" > "$log" 2>&1 &
    CURRENT_PID=$!

    if wait "$CURRENT_PID"; then
        exit_code=0
    else
        exit_code=$?
    fi

    CURRENT_PID=""

    seconds="$(
        sed -nE \
            's/.*perplexity: ([0-9]+([.][0-9]+)?([eE][+-]?[0-9]+)?) seconds per pass.*/\1/p' \
            "$log" |
            tail -n 1
    )"

    ppl="$(
        sed -nE \
            's/.*Final estimate: PPL = ([0-9]+([.][0-9]+)?([eE][+-]?[0-9]+)?).*/\1/p' \
            "$log" |
            tail -n 1
    )"

    if ((exit_code == 0)) && [[ -n "$seconds" && -n "$ppl" ]]; then
        status="ok"
        log_field=""
        rm -f -- "$log"
    else
        status="failed"
        log_field="$log"
        FAILED_TOTAL=$((FAILED_TOTAL + 1))
    fi

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$round" \
        "$position" \
        "$scenario" \
        "$status" \
        "$exit_code" \
        "$seconds" \
        "$ppl" \
        "$log_field" >> "$SAMPLES"

    printf '[round %s/%s position %s/%s] %s status=%s seconds=%s ppl=%s\n' \
        "$round" \
        "$RUNS" \
        "$position" \
        "$SCENARIO_COUNT" \
        "$scenario" \
        "$status" \
        "${seconds:-N/A}" \
        "${ppl:-N/A}"
}

for ((round=1; round<=RUNS; round++)); do
    # Rotate the starting scenario each round to reduce ordering bias.
    rotation=$(((round - 1) % SCENARIO_COUNT))

    for ((offset=0; offset<SCENARIO_COUNT; offset++)); do
        index=$(((rotation + offset) % SCENARIO_COUNT))

        run_sample \
            "$round" \
            "$((offset + 1))" \
            "${SCENARIOS[$index]}"

        echo "sleeping 60 seconds between samples to avoid CPU throttling"
        sleep 60
    done

    echo "sleeping 60 seconds between rounds to avoid CPU throttling"
    sleep 60
done

printf 'scenario\trequested\tvalid\tfailed\tavg_seconds_per_pass\tavg_ppl\n' > "$SUMMARY"

printf '\n%-27s %9s %7s %7s %22s %12s\n' \
    scenario \
    requested \
    valid \
    failed \
    avg_seconds_per_pass \
    avg_ppl

for scenario in "${SCENARIOS[@]}"; do
    stats="$(
        awk -F '\t' -v wanted="$scenario" '
            NR > 1 && $3 == wanted {
                requested++

                if ($4 == "ok") {
                    valid++
                    seconds += $6
                    ppl += $7
                }
            }

            END {
                failed = requested - valid

                if (valid > 0)
                    printf "%d\t%d\t%d\t%.2f\t%.4f",
                        requested,
                        valid,
                        failed,
                        seconds / valid,
                        ppl / valid
                else
                    printf "%d\t%d\t%d\tN/A\tN/A",
                        requested,
                        valid,
                        failed
            }
        ' "$SAMPLES"
    )"

    IFS=$'\t' read -r \
        requested \
        valid \
        failed \
        avg_seconds \
        avg_ppl <<< "$stats"

    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$scenario" \
        "$requested" \
        "$valid" \
        "$failed" \
        "$avg_seconds" \
        "$avg_ppl" >> "$SUMMARY"

    printf '%-27s %9s %7s %7s %22s %12s\n' \
        "$scenario" \
        "$requested" \
        "$valid" \
        "$failed" \
        "$avg_seconds" \
        "$avg_ppl"
done

if ((FAILED_TOTAL > 0)); then
    echo "benchmark completed with $FAILED_TOTAL failed sample(s); failed logs: $LOG_DIR" >&2
    exit 1
fi

echo "benchmark completed successfully; results: $OUTPUT_DIR"
