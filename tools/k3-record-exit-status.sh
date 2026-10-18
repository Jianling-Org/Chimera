#!/usr/bin/env bash

# Run a command, save its exact status in TRACE_EXIT_STATUS and a file, then
# return success so the caller can finish writing diagnostic summaries before
# exiting with TRACE_EXIT_STATUS itself.
run_and_record_exit() {
  local status_file=$1
  shift
  if "$@"; then
    TRACE_EXIT_STATUS=0
  else
    TRACE_EXIT_STATUS=$?
  fi
  printf '%s\n' "$TRACE_EXIT_STATUS" > "$status_file"
}
