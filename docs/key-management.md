# Key management

The signer generates its own Ed25519 key on first boot. The private seed
never leaves the device over UART; only the public key can be read
(`PUBKEY`). The host trusts a device after *enrolment*: it stores that
public key once and accepts only signatures that verify with it.

## Flash layout

| Region | Address | Size | Contents |
| --- | --- | --- | --- |
| Sectors 0–1 | `0x08000000` | 32 KB | Firmware image (`FLASH` region in `firmware/linker.ld`) |
| Sector 2 | `0x08008000` | 16 KB | Approval counter log A |
| Sector 3 | `0x0800C000` | 16 KB | Key store |
| Sector 4 | `0x08010000` | 64 KB | Approval counter log B |
| Sectors 5–11 | `0x08020000` | 896 KB | Unused (reserved for the bootloader work, roadmap step 2) |

The linker region ends where the data sectors start, so an image that
grows past 32 KB fails to link instead of overwriting the counter or the
key. (Before v0.4 the firmware region was 48 KB.)

## Key record (version 1)

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 4 | magic `0x59454B53` ("SKEY") |
| 4 | 4 | version `1` |
| 8 | 32 | Ed25519 seed (private) |
| 40 | 32 | Ed25519 public key |

The record is valid when the magic and version match and the public key
derived from the stored seed equals the stored public key. The magic word
is programmed last, so a record interrupted by a reset or power loss is
never taken for a complete one.

## Boot sequence

| Sector state | Action | UART line |
| --- | --- | --- |
| Magic word erased (`0xFFFFFFFF`) | Generate a key, erase the sector, write the record, read it back | `INFO KEY_GENERATED` |
| Valid record | Use it | `INFO KEY_LOADED` |
| Anything else | Refuse to sign; keep the record untouched | `WARN KEY_CORRUPT` |
| RNG or flash failure during generation | Refuse to sign | `WARN RNG_FAILURE` or `WARN FLASH_WRITE_FAILED`, then `WARN KEY_GENERATION_FAILED` |

Without a valid key, `PUBKEY` and `REQUEST3` answer `ERR NO_KEY`.

A corrupt record is deliberately **not** replaced automatically. Silently
generating a new key would hide tampering and would make every enrolled
host reject the device anyway. Recovery is an explicit act: erase the
chip (or sector 3) with a debugger, boot, and enrol again.

## Generation

1. Start PLL48CLK (HSI 16 MHz → VCO 384 MHz → /8 = 48 MHz), which the
   RNG needs; the CPU keeps running on HSI.
2. Read 64 bytes from the hardware RNG. Every 32-bit word is checked for
   seed and clock errors, and two consecutive equal words abort generation
   (continuous test from FIPS 140-2). The first word after enabling the
   RNG is discarded.
3. Seed = first 32 bytes of SHA-512 over those 64 bytes.
4. Derive the public key, write the record, verify it from flash.

All temporary copies of the seed are wiped from RAM.

## Approval counter

Every approval uses a new counter value that is part of the signed message
(see [protocol.md](protocol.md)). The value is written to flash *before*
signing, so a reset can skip a number but the device can never sign two
approvals with the same number.

The counter is an append-only log of 8-byte entries, `(value, ~value)`,
in sector 2 (2048 entries) and sector 4 (8192 entries):

- At boot both sectors are scanned. Entries whose second word is not the
  complement of the first (an interrupted write, a partly erased word) are
  ignored. The current value is the largest valid entry; new entries go
  after the last written slot of that sector, never on top of a torn one.
- When the active sector is full, the other sector is erased and the next
  entry is written at its start. The old sector keeps its smaller values
  until its own next erase, so a reset at any moment still yields the
  right value.
- One sector erase per 2048 or 8192 approvals; at 10 000 erase cycles per
  sector that is far beyond the life of a lab device.
- The counter stops at 4294967294 (`ERR COUNTER_FAILURE`).

`COUNTER` reports the last value used; the boot line `INFO COUNTER <n>`
shows the value found in flash.

## Enrolment

```bash
./scripts/signer-lab enroll --port /tmp/signer-uart --key-out device.hex
# ENROLLED ED25519-SHA256-61bd4534...
```

`enroll` refuses to overwrite an existing key file and refuses the public
RFC 8032 test key and blank keys. It is trust on first use: the host
believes whichever device answers on that port at that moment. Compare
the printed key ID with the device in a trusted setting (for example,
directly after flashing it yourself).

Every other command (`approve`, `accept`, `verify`) takes
`--public-key-file device.hex`.

## Simulation

Renode starts flash zero-filled, unlike a real chip. The test setup and
`simulation/*.resc` load erased images (`firmware/build/blank-16k.bin`,
`blank-64k.bin`) into sectors 2, 3 and 4 once, so every new Renode machine
behaves like a new, blank chip: it generates a new key and starts the
counter at 0. The reset macro reloads only the firmware image, so key and
counter survive resets, including watchdog resets. Tests that need a
prepared counter log build one with `tests/make_counter_log.py`.

## Real hardware

- Flashing a new firmware image with `openocd ... program` or `st-flash
  write` erases only the sectors the image covers; the counter and the key
  in sectors 2–4 survive. A mass erase destroys both: the device must be
  enrolled again (and its counter restarts at 1 under a new key).
- Enable read-out protection after enrolment, otherwise anyone with SWD
  access can read the seed:

  ```bash
  openocd -f interface/stlink.cfg -f target/stm32f4x.cfg \
    -c "init; reset halt; stm32f4x lock 0; reset run; shutdown"
  ```

  This sets RDP level 1: the debugger can no longer read flash. Going back
  to level 0 (`stm32f4x unlock 0`) mass-erases the chip, key included.
  Do not use level 2; it is permanent and disables debugging forever.
- RDP level 1 on STM32F4 is known to be defeatable with invasive
  techniques (fault injection). It raises the bar against casual
  extraction; it is not a secure element.
