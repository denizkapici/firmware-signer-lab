# Roadmap

Each step is planned as its own branch and pull request, with tests in
Renode and CI. Threat numbers refer to [threat-model.md](threat-model.md).

## Done

- Custom STM32F407 board in KiCad 10 (schematic, 2-layer PCB, ERC/DRC clean).
- Bare-metal C/assembly firmware, no HAL: UART, GPIO, SysTick, button
  state machine with debounce, cancellation and timeout.
- Ed25519 signing on Cortex-M4 (Monocypher), RFC 8032 known-answer test on
  the host and in Renode.
- V2 protocol binding request ID, digest, target and expiry (replaced by V3 in v0.4).
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

## 1b. Device-side monotonic counter — done (v0.4)

- Counter stored in flash before every signature and included in the
  signed message (protocol V3); never reused, survives resets.
- Append-only log of `(value, ~value)` entries over sectors 2 and 4 with
  rotation; torn entries are ignored. Firmware region reduced to 32 KB.
- Host rejects approvals whose counter is not newer than the last one
  accepted from the same device.
- Correction to the earlier plan: this does **not** protect against a
  rolled-back host database (T7), because the high-water mark is in the
  same database. Follow-ups: keep the mark on the deployment target, and
  an audit command that reports counter gaps (T7b).

## 2a. Secure bootloader — done (v0.5)

- Bootloader in sectors 0–1; application linked at slot A
  (`0x08020200`). Counter and key stay in sectors 2–4.
- Signed image format with a separate firmware signing key; the bootloader
  verifies size, Ed25519 signature and vector table before jumping.
- `signer-lab firmware keygen | public-key | sign | verify`; the C verifier
  and the Python tool are tested against each other.
- Renode tests for every rejection path.

## 2b. A/B updates and anti-rollback (T10)

- Update command over UART that writes the inactive slot (A or B).
- Boot state in flash: try the new slot once; the application confirms
  itself after it started correctly, otherwise the next reset falls back
  to the previous slot.
- Anti-rollback: refuse images whose version is lower than the highest
  version confirmed so far.
- Renode tests: update, failed update falls back, power loss during the
  update write, downgrade refused.

## 3. Standard signature format and release gate (T11)

- Emit signatures that standard tools can verify (minisign is Ed25519
  based), while keeping domain separation from `SIGNER-LAB-V3` messages.
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
