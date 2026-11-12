#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

# RENODE_BIN verilirse onu kullan; aksi halde kurulu Renode'u ara.
if [[ -n "${RENODE_BIN:-}" ]]; then
    RENODE_EXECUTABLE="$RENODE_BIN"
elif command -v renode >/dev/null 2>&1; then
    RENODE_EXECUTABLE="$(command -v renode)"
else
    RENODE_EXECUTABLE="$HOME/devops-lab/tools/renode-1.17.0/renode"
fi

if [[ ! -x "$RENODE_EXECUTABLE" ]]; then
    printf 'Renode bulunamadi: %s\n' "$RENODE_EXECUTABLE" >&2
    printf 'RENODE_BIN ile Renode calistirilabilir dosyasini belirt.\n' >&2
    exit 1
fi

UART_PATH="/tmp/signer-uart"

# Yalnizca hedefi artik bulunmayan eski sembolik baglantiyi temizle.
if [[ -L "$UART_PATH" && ! -e "$UART_PATH" ]]; then
    rm -- "$UART_PATH"
fi

if [[ -e "$UART_PATH" || -L "$UART_PATH" ]]; then
    printf '%s zaten mevcut. Acik Renode oturumunu kontrol et.\n' \
        "$UART_PATH" >&2
    exit 1
fi

bash "$PROJECT_ROOT/scripts/build-firmware.sh"

printf '\nRenode baslatiliyor.\n'
printf 'UART: %s\n' "$UART_PATH"
printf 'Cikmak icin Renode Monitor ekraninda quit yaz.\n\n'

exec "$RENODE_EXECUTABLE" \
    --console \
    --disable-gui \
    "$PROJECT_ROOT/simulation/run-uart.resc"
