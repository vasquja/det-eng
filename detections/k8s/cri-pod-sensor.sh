#!/bin/sh
# Node runtime sensor for the TRR9003 lab: records every pod sandbox the
# container runtime (CRI) reports, with its annotations.
#
# It stands in for a runtime security or EDR agent with container context. Such
# an agent reports a sandbox when it starts; this lab version polls the CRI with
# crictl and appends one snapshot per line. The validator keeps the first
# sighting of each sandbox id, so a sandbox that lives longer than one poll
# interval is seen, including the invalid-namespace static pod whose mirror pod
# the API server rejects (TRR9003 Strategy 1).
#
# Run on the node (root, crictl configured for the runtime socket):
#   cri-pod-sensor.sh once                  one snapshot to stdout
#   cri-pod-sensor.sh watch FILE [SECONDS]  append a snapshot every SECONDS (1)
#
# Each line is `crictl pods -o json` with its newlines removed: {"items": [...]}.
set -eu

snapshot() {
  crictl pods -o json | tr -d '\n'
  echo
}

case "${1:-once}" in
  once)
    snapshot
    ;;
  watch)
    out="${2:?usage: $0 watch FILE [SECONDS]}"
    every="${3:-1}"
    while :; do
      snapshot >> "$out" || true
      sleep "$every"
    done
    ;;
  *)
    echo "usage: $0 once | watch FILE [SECONDS]" >&2
    exit 2
    ;;
esac
