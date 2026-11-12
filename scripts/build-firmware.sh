#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

for tool in arm-none-eabi-gcc arm-none-eabi-objcopy arm-none-eabi-size; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        printf 'Gerekli arac bulunamadi: %s\n' "$tool" >&2
        exit 1
    fi
done

mkdir -p firmware/build

arm-none-eabi-gcc \
    -mcpu=cortex-m4 -mthumb \
    -std=c11 -O2 -g3 \
    -Wall -Wextra \
    -ffreestanding -fno-builtin \
    -ffunction-sections -fdata-sections \
    -fno-unwind-tables -fno-asynchronous-unwind-tables \
    -DSIGNER_DEMO_KEY=1 \
    -Ifirmware/vendor/monocypher \
    -nostdlib \
    -T firmware/linker.ld \
    -Wl,--gc-sections \
    -Wl,-Map=firmware/build/signer.map \
    firmware/startup.s \
    firmware/main.c \
    firmware/runtime.c \
    firmware/signer_crypto.c \
    firmware/vendor/monocypher/monocypher.c \
    firmware/vendor/monocypher/monocypher-ed25519.c \
    -lgcc \
    -o firmware/build/signer.elf

arm-none-eabi-objcopy \
    -O binary \
    firmware/build/signer.elf \
    firmware/build/signer.bin

arm-none-eabi-size firmware/build/signer.elf

printf '\nDerleme tamamlandi: DEMO KEY BUILD\n'
printf 'ELF: firmware/build/signer.elf\n'
printf 'BIN: firmware/build/signer.bin\n'
