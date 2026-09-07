#!/usr/bin/env bash
set -e

printf '%s\n' "[system-config-inspector] Starting read-only runtime inspection..."
printf '%s\n' "[system-config-inspector] Mode=${INSPECTOR_MODE:-once}"

exec python3 "$(dirname "$0")/system_info.py" "${@}"
