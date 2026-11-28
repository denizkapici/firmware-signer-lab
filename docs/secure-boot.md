# Secure boot

Since v0.5 the signer runs behind a small bootloader. On every reset,
including watchdog resets, the bootloader checks the Ed25519 signature of
the application in slot A and starts it only if the signature is valid for
the **firmware signing key** compiled into the bootloader. Otherwise it
prints why on the UART and halts with the LED blinking slowly.

This closes the gap "anyone who can write flash can run their own code
that reads the approval key" for everything except the bootloader itself
(see [threat-model.md](threat-model.md), T10).

## Two different keys

| Key | Where it lives | Signs |
| --- | --- | --- |
| Device approval key | Generated on the device, flash sector 3 ([key-management.md](key-management.md)) | Approvals (`SIGNER-LAB-V3 ...`) |
| Firmware signing key | With whoever releases firmware (developer, CI secret); public half compiled into the bootloader | Application images (`SIGNER-LAB-FW1 ...`) |

The device key cannot be used for firmware: it sits in flash that the
application can read, so a compromised application could sign its own
replacement. The firmware key never touches the device.

## Flash layout

| Region | Address | Size | Contents |
| --- | --- | --- | --- |
| Sectors 0–1 | `0x08000000` | 32 KB | Bootloader (`firmware/boot/boot.ld`) |
| Sector 2 | `0x08008000` | 16 KB | Approval counter log A |
| Sector 3 | `0x0800C000` | 16 KB | Device key store |
| Sector 4 | `0x08010000` | 64 KB | Approval counter log B |
| Sector 5 | `0x08020000` | 128 KB | Slot A: signed application image |
| Sector 6 | `0x08040000` | 128 KB | Slot B: reserved for A/B updates (step 2b) |

The application is linked at `0x08020200` (`firmware/app.ld`), right after
the 512-byte image header; 512 bytes keeps its 98-entry vector table
aligned for `VTOR`.

## Image format (version 1)

| Offset | Size | Field |
| --- | --- | --- |
| `0x000` | 4 | magic `0x49574653` ("SFWI") |
| `0x004` | 4 | header version `1` |
| `0x008` | 4 | application size in bytes (multiple of 4) |
| `0x00C` | 4 | firmware version (for anti-rollback in step 2b) |
| `0x010` | 48 | reserved, must be zero |
| `0x040` | 64 | Ed25519 signature |
| `0x080` | 384 | `0xFF` padding (not signed) |
| `0x200` | size | application: vector table, code, data |

Signed message (79 bytes):

    "SIGNER-LAB-FW1 " || SHA-512(header bytes 0x000..0x03F || application)

Pre-hashing lets the bootloader hash the image straight from flash with a
fixed amount of RAM. Size and version are covered by the signature, so
neither can be changed without invalidating the image.

## What the bootloader checks, in order

| Check | Failure line |
| --- | --- |
| Magic word not erased | `BOOT SLOT A EMPTY` |
| Magic, header version, reserved bytes | `BOOT SLOT A BAD_HEADER` |
| Size non-zero, word-aligned, fits the slot (checked *before* hashing, so a forged size cannot make it read past the slot) | `BOOT SLOT A BAD_SIZE` |
| Ed25519 signature | `BOOT SLOT A BAD_SIGNATURE` |
| Initial stack pointer in RAM and 8-byte aligned; reset handler is Thumb and inside the image | `BOOT SLOT A BAD_VECTORS` |

On success it prints `BOOT SLOT A OK version=<n>`, sets `VTOR` to the
application's vector table, loads the initial stack pointer and jumps.
The bootloader uses no interrupts and does not start the watchdog; the
application does both itself.

## Building and signing

```bash
./scripts/build-firmware.sh
```

builds both images and writes `firmware/build/signer-slot-a.bin`, the
signed slot image. Signing key and version come from the environment:

| Variable | Default |
| --- | --- |
| `FIRMWARE_SIGNING_KEY` | `firmware/build/dev-firmware-signing.key`, created on first build |
| `FIRMWARE_VERSION` | `1` |

The development key is fine for simulation and CI (CI creates a new one on
every run). **Never put a bootloader built with the development key on a
real board**: the key is an ordinary file in the build directory.

The same steps by hand:

```bash
./scripts/signer-lab firmware keygen --out release.key        # once; keep it secret
./scripts/signer-lab firmware public-key --key release.key --c-header firmware/build/generated/firmware_public_key.h
./scripts/signer-lab firmware sign firmware/build/signer.bin --key release.key --version 2 --out slot-a.bin
./scripts/signer-lab firmware verify slot-a.bin --public-key-file firmware/build/firmware-public-key.hex
```

`firmware sign` re-checks the result exactly like the bootloader and
refuses to write an image that would not boot. `tests/test_firmware_image.py`
builds `firmware/boot/image.c` for the host and checks that the C code
and the Python tool accept and reject the same images.

## Simulation

Renode loads the bootloader ELF on every reset (the `reset` macro) and the
signed slot image once, like real flash. Loading an ELF in Renode also sets
the start address and replaces its symbol table, so the application ELF is
deliberately not loaded; the one test that needs an application symbol
reads its address with `arm-none-eabi-nm`.

`tests/boot.robot` covers: valid image, changed code byte, changed version
field, changed signature, image signed with another key, empty slot,
zero-filled slot, non-zero reserved byte, oversized length, and a
correctly signed image with an invalid entry point.

## Limits (planned for step 2b)

- Only slot A; no update path over UART, no A/B switch, no rollback if a
  new image fails to start.
- No anti-rollback: an older, correctly signed image still boots. The
  version field is signed and ready for it.
- The bootloader itself is not protected: whoever can write sectors 0–1
  (SWD) can replace it. On real hardware, write-protect sectors 0–1 (flash
  option bytes) and enable read-out protection.
