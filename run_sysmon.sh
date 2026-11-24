#!/usr/bin/env bash

set -Eeuo pipefail

# Resolve the directory of this script (handles cron & relative paths)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Prefer the project virtual environment. SYSMON_PYTHON can override it.
if [[ -n "${SYSMON_PYTHON:-}" ]]; then
    PYTHON_BIN="$SYSMON_PYTHON"
elif [[ -x "$SCRIPT_DIR/.venv/bin/python" ]]; then
    PYTHON_BIN="$SCRIPT_DIR/.venv/bin/python"
else
    PYTHON_BIN="$(command -v python3 || true)"
fi

if [[ -z "$PYTHON_BIN" ]]; then
    echo "SysMon failed: python3 was not found" >&2
    exit 127
fi

CONFIG_PATH="${SYSMON_CONFIG:-$SCRIPT_DIR/config.json}"
exec "$PYTHON_BIN" "$SCRIPT_DIR/sysmon.py" --config "$CONFIG_PATH" "$@"
