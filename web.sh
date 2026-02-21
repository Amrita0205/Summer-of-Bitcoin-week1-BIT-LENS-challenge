#!/usr/bin/env bash
set -euo pipefail

PORT="${PORT:-3000}"
cd "$(dirname "$0")"

# Use python on Windows, python3 on Linux
if command -v python3 >/dev/null 2>&1; then
  exec python3 web/server.py "$PORT"
else
  exec python web/server.py "$PORT"
fi