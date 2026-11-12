#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

command -v gcc >/dev/null 2>&1 || {
    printf 'gcc bulunamadi.\n' >&2
    exit 1
}

mkdir -p firmware/build

gcc \
    -std=c11 -O2 -Wall -Wextra \
    -Ifirmware/vendor/monocypher \
    tests/test_ed25519.c \
    firmware/vendor/monocypher/monocypher.c \
    firmware/vendor/monocypher/monocypher-ed25519.c \
    -o firmware/build/test-ed25519-host

./firmware/build/test-ed25519-host
