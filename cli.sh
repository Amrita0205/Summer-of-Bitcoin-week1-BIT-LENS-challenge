#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# cli.sh — Chain Lens: Bitcoin Transaction & Block Analyzer
#
# Usage:
#   ./cli.sh <fixture.json>                          JSON output (grader mode)
#   ./cli.sh --pretty <fixture.json>                 Beautiful terminal output
#   ./cli.sh --block <blk.dat> <rev.dat> <xor.dat>  Block mode (JSON)
#   ./cli.sh --pretty-block <blk> <rev> <xor>        Block mode (beautiful)
###############################################################################

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

error_json() {
  printf '{"ok":false,"error":{"code":"%s","message":"%s"}}\n' "$1" "$2"
}

# ── Pretty transaction display ────────────────────────────────────────────────
if [[ "${1:-}" == "--pretty" ]]; then
  shift
  if [[ $# -lt 1 ]]; then
    echo "Usage: ./cli.sh --pretty <fixture.json>" >&2; exit 1
  fi
  FIXTURE="$1"
  if [[ ! -f "$FIXTURE" ]]; then
    echo "Error: File not found: $FIXTURE" >&2; exit 1
  fi
  mkdir -p out
  python3 "$SCRIPT_DIR/pretty_cli.py" --pretty "$FIXTURE"
  exit 0
fi

# ── Pretty block display ──────────────────────────────────────────────────────
if [[ "${1:-}" == "--pretty-block" ]]; then
  shift
  if [[ $# -lt 3 ]]; then
    echo "Usage: ./cli.sh --pretty-block <blk.dat> <rev.dat> <xor.dat>" >&2; exit 1
  fi
  mkdir -p out
  python3 "$SCRIPT_DIR/pretty_cli.py" --pretty-block "$1" "$2" "$3"
  exit 0
fi

# ── Block mode (JSON for grader) ──────────────────────────────────────────────
if [[ "${1:-}" == "--block" ]]; then
  shift
  if [[ $# -lt 3 ]]; then
    error_json "INVALID_ARGS" "Block mode requires: --block <blk.dat> <rev.dat> <xor.dat>"
    exit 1
  fi
  BLK_FILE="$1"; REV_FILE="$2"; XOR_FILE="$3"
  for f in "$BLK_FILE" "$REV_FILE" "$XOR_FILE"; do
    if [[ ! -f "$f" ]]; then
      error_json "FILE_NOT_FOUND" "File not found: $f"
      exit 1
    fi
  done
  mkdir -p out
  python3 "$SCRIPT_DIR/block_analyzer.py" "$BLK_FILE" "$REV_FILE" "$XOR_FILE"
  exit 0
fi

# ── Transaction mode (JSON for grader) ───────────────────────────────────────
if [[ $# -lt 1 ]]; then
  error_json "INVALID_ARGS" "Usage: cli.sh <fixture.json>"
  exit 1
fi

FIXTURE="$1"
if [[ ! -f "$FIXTURE" ]]; then
  error_json "FILE_NOT_FOUND" "Fixture file not found: $FIXTURE"
  exit 1
fi

mkdir -p out
python3 "$SCRIPT_DIR/analyzer.py" "$FIXTURE"