#!/usr/bin/env bash
set -euo pipefail

if ! command -v ns >/dev/null 2>&1; then
  echo "ERROR: NS-2 ('ns') is not installed in this Ubuntu/WSL environment."
  echo "Install it via: sudo apt-get update && sudo apt-get install -y ns2"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

for LOAD in low normal heavy; do
  echo "[run_ns2] Running NS-2 simulation for load=$LOAD..."
  ns emergency.tcl "$LOAD"
  if [ -f "cwnd_${LOAD}.tr" ]; then
    while read -r t val; do
      [ -n "$t" ] && echo "# CWND $t $val" >> "real_trace_${LOAD}.tr"
    done < "cwnd_${LOAD}.tr"
  fi
  echo "[run_ns2] Generated real_trace_${LOAD}.tr"
done

echo "[run_ns2] All three loads complete. Upload real_trace_*.tr in the ECAS NS-2 tab."

