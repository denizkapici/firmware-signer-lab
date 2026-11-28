#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

mkdir -p firmware/build

arm-none-eabi-gcc \
    -mcpu=cortex-m4 -mthumb \
    -std=c11 -O2 -g3 -Wall -Wextra \
    -ffreestanding -fno-builtin \
    -ffunction-sections -fdata-sections \
    -fno-unwind-tables -fno-asynchronous-unwind-tables \
    -nostdlib \
    -Ifirmware/vendor/monocypher \
    -Lfirmware \
    -T firmware/boot/boot.ld \
    -Wl,--gc-sections \
    -Wl,-Map=firmware/build/crypto-test.map \
    firmware/startup.s \
    firmware/runtime.c \
    tests/ed25519_arm.c \
    firmware/vendor/monocypher/monocypher.c \
    firmware/vendor/monocypher/monocypher-ed25519.c \
    -lgcc \
    -o firmware/build/crypto-test.elf

arm-none-eabi-size firmware/build/crypto-test.elf
