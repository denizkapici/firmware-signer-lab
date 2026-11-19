# Key management

The signer generates its own Ed25519 key on first boot. The private seed
never leaves the device over UART; only the public key can be read
(`PUBKEY`). The host trusts a device after *enrolment*: it stores that
public key once and accepts only signatures that verify with it.

## Flash layout

| Region | Address | Size | Contents |
| --- | --- | --- | --- |
| Sectors 0–2 | `0x08000000` | 48 KB | Firmware image (`FLASH` region in `firmware/linker.ld`) |
| Sector 3 | `0x0800C000` | 16 KB | Key store |
| Sectors 4–11 | `0x08010000` | 960 KB | Unused (reserved for the bootloader work, roadmap step 2) |

The linker region ends at the key store, so an image that grows into
sector 3 fails to link instead of overwriting the key.

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

Without a valid key, `PUBKEY` and `REQUEST2` answer `ERR NO_KEY`.

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
`simulation/*.resc` load `firmware/build/keystore-blank.bin` (16 KB of
`0xFF`) into sector 3 once, so every new Renode machine behaves like a
new, blank chip and generates a new key. The reset macro reloads only the
firmware image, so the key survives resets, including watchdog resets.

## Real hardware

- Flashing a new firmware image with `openocd ... program` or `st-flash
  write` erases only the sectors the image covers; the key in sector 3
  survives. A mass erase destroys it and the device enrols as new.
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
