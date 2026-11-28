#!/usr/bin/env bash
# Build the secure bootloader and the application, and sign the
# application into a slot image the bootloader accepts.
#
# Environment:
#   FIRMWARE_SIGNING_KEY  firmware signing key file (hex seed). Default: a
#                         development key in firmware/build, created on
#                         first use. Never use the development key for a
#                         real device.
#   FIRMWARE_VERSION      image version number (default 1).
#   SIGNER_HOST_PYTHON    Python with the 'cryptography' package.
set -euo pipefail

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

for tool in arm-none-eabi-gcc arm-none-eabi-objcopy arm-none-eabi-size; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        printf 'Required tool not found: %s\n' "$tool" >&2
        exit 1
    fi
done

BUILD=firmware/build
GENERATED="$BUILD/generated"
mkdir -p "$BUILD/app" "$BUILD/boot" "$GENERATED"

SIGNING_KEY="${FIRMWARE_SIGNING_KEY:-$BUILD/dev-firmware-signing.key}"
VERSION="${FIRMWARE_VERSION:-1}"

if [ -z "${FIRMWARE_SIGNING_KEY:-}" ] && [ ! -f "$SIGNING_KEY" ]; then
    ./scripts/signer-lab firmware keygen --out "$SIGNING_KEY" >/dev/null
    printf 'Created development firmware signing key: %s\n' "$SIGNING_KEY"
fi
./scripts/signer-lab firmware public-key --key "$SIGNING_KEY" \
    --out "$BUILD/firmware-public-key.hex" \
    --c-header "$GENERATED/firmware_public_key.h" >/dev/null

COMMON_FLAGS=(
    -mcpu=cortex-m4 -mthumb
    -std=c11 -O2 -g3
    -ffreestanding -fno-builtin
    -ffunction-sections -fdata-sections
    -fno-unwind-tables -fno-asynchronous-unwind-tables
    -Ifirmware -Ifirmware/boot -I"$GENERATED" -Ifirmware/vendor/monocypher
)

# Project code is held to stricter warnings than the vendored library.
PROJECT_WARNINGS=(
    -Wall -Wextra -Werror
    -Wshadow -Wconversion -Wcast-qual -Wstrict-prototypes
    -Wmissing-prototypes -Wundef
)

VENDOR_SOURCES=(
    firmware/vendor/monocypher/monocypher.c
    firmware/vendor/monocypher/monocypher-ed25519.c
)

# compile OUTPUT_DIR "PROJECT SOURCES..." ; sets OBJECTS
compile() {
    local output="$1"
    shift
    OBJECTS=()
    for source in "$@"; do
        local object="$output/$(basename "${source%.*}").o"
        arm-none-eabi-gcc "${COMMON_FLAGS[@]}" "${PROJECT_WARNINGS[@]}" \
            -c "$source" -o "$object"
        OBJECTS+=("$object")
    done
    for source in "${VENDOR_SOURCES[@]}"; do
        local object="$output/$(basename "${source%.*}").o"
        arm-none-eabi-gcc "${COMMON_FLAGS[@]}" -Wall -Wextra \
            -c "$source" -o "$object"
        OBJECTS+=("$object")
    done
}

# link LINKER_SCRIPT OUTPUT_BASENAME
link() {
    arm-none-eabi-gcc \
        -mcpu=cortex-m4 -mthumb \
        -nostdlib \
        -Lfirmware \
        -T "$1" \
        -Wl,--gc-sections \
        -Wl,-Map="$BUILD/$2.map" \
        "${OBJECTS[@]}" \
        -lgcc \
        -o "$BUILD/$2.elf"
    arm-none-eabi-objcopy -O binary "$BUILD/$2.elf" "$BUILD/$2.bin"
}

compile "$BUILD/app" \
    firmware/startup.s \
    firmware/main.c \
    firmware/system.c \
    firmware/gpio.c \
    firmware/uart.c \
    firmware/protocol.c \
    firmware/approval.c \
    firmware/fault.c \
    firmware/rng.c \
    firmware/flash.c \
    firmware/keystore.c \
    firmware/counter.c \
    firmware/runtime.c \
    firmware/signer_crypto.c
link firmware/app.ld signer

compile "$BUILD/boot" \
    firmware/startup.s \
    firmware/boot/main.c \
    firmware/boot/image.c \
    firmware/runtime.c
link firmware/boot/boot.ld bootloader

./scripts/signer-lab firmware sign "$BUILD/signer.bin" \
    --key "$SIGNING_KEY" --version "$VERSION" --out "$BUILD/signer-slot-a.bin"

arm-none-eabi-size "$BUILD/bootloader.elf" "$BUILD/signer.elf"

# Factory-blank flash (0xFF) for the data sectors: 16 KB (sectors 2, 3)
# and 64 KB (sector 4). Renode starts flash zero-filled; tests load these
# once to emulate a new chip.
head -c 16384 /dev/zero | tr '\0' '\377' > "$BUILD/blank-16k.bin"
head -c 65536 /dev/zero | tr '\0' '\377' > "$BUILD/blank-64k.bin"

printf '\nBuild finished (device-generated key, secure boot)\n'
printf 'Bootloader:  %s\n' "$BUILD/bootloader.elf"
printf 'Application: %s (signed slot image: %s)\n' "$BUILD/signer.elf" "$BUILD/signer-slot-a.bin"
printf 'Firmware public key: %s\n' "$(cat "$BUILD/firmware-public-key.hex")"
