#!/usr/bin/env bash
# Test helper: run a live script with its output on a pipe to a reader that reads only
# the first lines and then goes away (`script 2>&1 | head -N`). Not an emulation script.
#   pipe_to_head.sh <script> <N> [arguments of the script]
set -uo pipefail
script="$1"; lines="$2"; shift 2
bash "$script" "$@" 2>&1 | head -n "$lines" >/dev/null
