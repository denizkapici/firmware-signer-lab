#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

for tool in arm-none-eabi-gcc arm-none-eabi-objcopy arm-none-eabi-size; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        printf 'Required tool not found: %s\n' "$tool" >&2
        exit 1
    fi
done

mkdir -p firmware/build

SOURCES=(
    firmware/startup.s
    firmware/main.c
    firmware/system.c
    firmware/gpio.c
    firmware/uart.c
    firmware/protocol.c
    firmware/approval.c
    firmware/fault.c
    firmware/rng.c
    firmware/flash.c
    firmware/keystore.c
    firmware/runtime.c
    firmware/signer_crypto.c
)

VENDOR_SOURCES=(
    firmware/vendor/monocypher/monocypher.c
    firmware/vendor/monocypher/monocypher-ed25519.c
)

COMMON_FLAGS=(
    -mcpu=cortex-m4 -mthumb
    -std=c11 -O2 -g3
    -ffreestanding -fno-builtin
    -ffunction-sections -fdata-sections
    -fno-unwind-tables -fno-asynchronous-unwind-tables
    -Ifirmware -Ifirmware/vendor/monocypher
)

# Project code is held to stricter warnings than the vendored library.
PROJECT_WARNINGS=(
    -Wall -Wextra -Werror
    -Wshadow -Wconversion -Wcast-qual -Wstrict-prototypes
    -Wmissing-prototypes -Wundef
)

OBJECTS=()
for source in "${SOURCES[@]}"; do
    object="firmware/build/$(basename "${source%.*}").o"
    arm-none-eabi-gcc "${COMMON_FLAGS[@]}" "${PROJECT_WARNINGS[@]}" \
        -c "$source" -o "$object"
    OBJECTS+=("$object")
done

for source in "${VENDOR_SOURCES[@]}"; do
    object="firmware/build/$(basename "${source%.*}").o"
    arm-none-eabi-gcc "${COMMON_FLAGS[@]}" -Wall -Wextra \
        -c "$source" -o "$object"
    OBJECTS+=("$object")
done

arm-none-eabi-gcc \
    -mcpu=cortex-m4 -mthumb \
    -nostdlib \
    -T firmware/linker.ld \
    -Wl,--gc-sections \
    -Wl,-Map=firmware/build/signer.map \
    "${OBJECTS[@]}" \
    -lgcc \
    -o firmware/build/signer.elf

arm-none-eabi-objcopy -O binary \
    firmware/build/signer.elf firmware/build/signer.bin

arm-none-eabi-size firmware/build/signer.elf

# Factory-blank contents of the key store sector (16 KB of 0xFF). Renode
# starts flash zero-filled; tests load this once to emulate a new chip.
head -c 16384 /dev/zero | tr '\0' '\377' > firmware/build/keystore-blank.bin

printf '\nBuild finished (device-generated key)\n'
printf 'ELF: firmware/build/signer.elf\n'
printf 'BIN: firmware/build/signer.bin\n'
