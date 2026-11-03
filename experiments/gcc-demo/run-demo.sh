#!/bin/bash
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec /usr/bin/python3 -B "$HERE/demo.py" "$@"
