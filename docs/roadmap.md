# Roadmap

Each step is planned as its own branch and pull request, with tests in
Renode and CI. Threat numbers refer to [threat-model.md](threat-model.md).

## Done

- Custom STM32F407 board in KiCad 10 (schematic, 2-layer PCB, ERC/DRC clean).
- Bare-metal C/assembly firmware, no HAL: UART, GPIO, SysTick, button
  state machine with debounce, cancellation and timeout.
- Ed25519 signing on Cortex-M4 (Monocypher), RFC 8032 known-answer test on
  the host and in Renode.
- V2 protocol binding request ID, digest, target and expiry.
- Host client with receipts and single-use acceptance in SQLite.
- Renode simulation and Robot Framework tests, run in GitHub Actions.
- Revision 0.2: firmware split into modules, interrupt-driven UART, full
  vector table, fault reporting, watchdog; V1 removed; Python package with
  one CLI; pinned CI actions, Dependabot, cppcheck, ruff; documentation.

## 1a. Device-generated key and enrolment — done (v0.3)

- Ed25519 seed generated on first boot from the STM32 hardware RNG
  (PLL48CLK, health checks, SHA-512 conditioning) and stored in flash
  sector 3; corrupt records block signing and are never replaced silently.
- `PUBKEY` command; host `enroll` command; host refuses the RFC 8032 test
  key. The demo key is gone from the firmware.
- Read-out protection documented for real hardware.

## 1b. Device-side monotonic counter (T3, T7)

- Counter in flash, incremented before every signature and included in
  the signed message (protocol V3), so the device itself never signs two
  approvals with the same counter value.
- Host stores the last counter seen per device and rejects anything older.
- Flash wear: append-only counter log within a sector, erased when full.

## 2. Secure bootloader (T10)

- Small bootloader at the start of flash; application moves to a second
  slot.
- The bootloader verifies an Ed25519 signature over the application image
  before jumping to it; an invalid image is never started.
- A/B slots with rollback if the new image does not confirm itself.
- Renode tests: valid image boots, tampered image is refused, power loss
  during update recovers.

## 3. Standard signature format and release gate (T11)

- Emit signatures that standard tools can verify (minisign is Ed25519
  based), while keeping domain separation from `SIGNER-LAB-V2` messages.
- A release workflow: on a version tag, build, request approval, and
  publish the artifact only together with a valid approval.
- Optional SLSA / in-toto provenance statement signed by the device.

## 4. Later

- Small I2C OLED showing target and a digest fingerprint (T5).
- Simulated secure element in Renode (Python peripheral) to hold the key.
- Signing service with policy (which project may request which target)
  and a hash-chained audit log.
- Fuzzing the firmware command parser with libFuzzer (T9).
- Board revision B: USB device, reverse-polarity and ESD protection,
  mounting holes, test points, USB-UART bridge.
