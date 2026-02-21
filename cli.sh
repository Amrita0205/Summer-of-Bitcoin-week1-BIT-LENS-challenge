#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# cli.sh — Bitcoin transaction / block analyzer CLI
#
# Usage:
#   ./cli.sh <fixture.json>                          Single-transaction mode
#   ./cli.sh --block <blk.dat> <rev.dat> <xor.dat>  Block mode
###############################################################################

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

error_json() {
  printf '{"ok":false,"error":{"code":"%s","message":"%s"}}\n' "$1" "$2"
}

# --- Block mode ---
if [[ "${1:-}" == "--block" ]]; then
  shift
  if [[ $# -lt 3 ]]; then
    error_json "INVALID_ARGS" "Block mode requires: --block <blk.dat> <rev.dat> <xor.dat>"
    exit 1
  fi

  BLK_FILE="$1"
  REV_FILE="$2"
  XOR_FILE="$3"

  for f in "$BLK_FILE" "$REV_FILE" "$XOR_FILE"; do
    if [[ ! -f "$f" ]]; then
      error_json "FILE_NOT_FOUND" "File not found: $f"
      exit 1
    fi
  done

  mkdir -p out

  if ! python3 "$SCRIPT_DIR/block_analyzer.py" "$BLK_FILE" "$REV_FILE" "$XOR_FILE"; then
    exit 1
  fi
  exit 0
fi

# --- Single-transaction mode ---
if [[ $# -lt 1 ]]; then
  error_json "INVALID_ARGS" "Usage: cli.sh <fixture.json> or cli.sh --block <blk> <rev> <xor>"
  exit 1
fi

FIXTURE="$1"

if [[ ! -f "$FIXTURE" ]]; then
  error_json "FILE_NOT_FOUND" "Fixture file not found: $FIXTURE"
  exit 1
fi

mkdir -p out

python3 "$SCRIPT_DIR/analyzer.py" "$FIXTURE"