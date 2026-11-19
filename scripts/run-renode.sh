#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

# Use RENODE_BIN if set, otherwise look for an installed Renode.
if [[ -n "${RENODE_BIN:-}" ]]; then
    RENODE_EXECUTABLE="$RENODE_BIN"
elif command -v renode >/dev/null 2>&1; then
    RENODE_EXECUTABLE="$(command -v renode)"
else
    RENODE_EXECUTABLE="$HOME/devops-lab/tools/renode-1.17.0/renode"
fi

if [[ ! -x "$RENODE_EXECUTABLE" ]]; then
    printf 'Renode not found: %s\n' "$RENODE_EXECUTABLE" >&2
    printf 'Set RENODE_BIN to the Renode executable.\n' >&2
    exit 1
fi

UART_PATH="/tmp/signer-uart"

# Remove only a stale symlink whose target no longer exists.
if [[ -L "$UART_PATH" && ! -e "$UART_PATH" ]]; then
    rm -- "$UART_PATH"
fi

if [[ -e "$UART_PATH" || -L "$UART_PATH" ]]; then
    printf '%s already exists. Is another Renode session running?\n' \
        "$UART_PATH" >&2
    exit 1
fi

bash "$PROJECT_ROOT/scripts/build-firmware.sh"

printf '\nStarting Renode.\n'
printf 'UART: %s\n' "$UART_PATH"
printf 'Type quit in the Renode monitor to exit.\n\n'

exec "$RENODE_EXECUTABLE" \
    --console \
    --disable-gui \
    "$PROJECT_ROOT/simulation/run-uart.resc"
