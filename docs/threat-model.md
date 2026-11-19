# Threat model

This document states what the signer is meant to protect against, what it
does not protect against today, and which roadmap item closes each gap.
Since v0.3 the device generates its own key on first boot; see
[key-management.md](key-management.md).

## What is being protected

A release pipeline produces a file (firmware image, binary, container
digest). Before the file is deployed to a *target* (for example
`staging` or `production`), a human must approve that exact file for
that exact target, once, within a time window.

Assets:

1. **The signing key.** Whoever holds it can forge approvals.
2. **The approval decision.** It must come from a physical button press.
3. **The binding.** An approval must not be reusable for another file,
   another target, after expiry, or a second time.

## Trust boundaries

```
 CI / release job ──► host (signer-lab CLI + SQLite) ──UART──► signer device
     untrusted             partly trusted                         trusted
```

- The **device** holds the key and decides when to sign.
- The **host** registers operations, verifies signatures, enforces expiry
  and single use. It is trusted for those checks but must not be able to
  sign on its own.
- The **CI job** that requests approval is treated as potentially
  compromised.

## Threats and current status

| # | Threat | Status today | Mitigation / plan |
| --- | --- | --- | --- |
| T1 | Attacker reads the private key | **Partly mitigated.** The key is generated on the device from the hardware RNG and no command exports it. It is stored in plain flash: anyone with SWD access can read it unless read-out protection (RDP level 1) is enabled, and RDP 1 can be defeated with invasive attacks. | Enable RDP after enrolment (documented). A secure element (roadmap 4) would keep the key out of MCU flash. |
| T2 | Host or CI forges an approval without the device | Mitigated while the key is secret (T1): the host only accepts signatures that verify against the enrolled public key, and refuses the public RFC 8032 test key. | — |
| T2a | Wrong device enrolled (attacker answers `PUBKEY` during enrolment) | **Not mitigated.** Enrolment is trust on first use. | Compare the printed key ID in a trusted setting; device attestation is out of scope. |
| T3 | Replay an old approval | Mitigated on the host: each operation has a 128-bit random ID and is consumed atomically in SQLite; a second `accept` fails. | Roadmap 1b: monotonic counter on the device, so replay protection does not depend only on the host database. |
| T4 | Reuse an approval for another file / target / later time | Mitigated: digest, target and expiry are all inside the signed message, and the host re-hashes the file before consuming. | — |
| T5 | Compromised host sends the digest of a *malicious* file, and the user presses the button | **Not mitigated.** The device has no display, so the user cannot see what they approve. The button proves *presence*, not *intent*. | Roadmap 4: small display showing target and a short digest fingerprint. Until then: one request at a time, a short 5 s window, and the LED signal. |
| T6 | Approval without a human (automated button press) | Not mitigated in simulation (the tests press the button). On hardware, requires physical access. | Physical button wired directly to the MCU; no software path can set PA0. |
| T7 | Host database rolled back or edited | **Not mitigated.** Restoring an old database re-opens consumed approvals. | Roadmap 1b (device-side counter); protect the database file. |
| T7a | Key store corrupted or tampered with | Mitigated: the record is checked by re-deriving the public key; a bad record blocks signing and is never replaced silently. | — |
| T8 | Host clock moved backwards | **Not mitigated.** Expiry is checked against the host clock; the device has no trusted time. | Out of scope for now; document and monitor. |
| T9 | Malformed or oversized input crashes the firmware | Mitigated: strict canonical parsing, 255-character line limit, interrupt-driven ring buffer with overflow detection, tests for malformed input. A CPU fault is reported over UART and the watchdog resets the device. | Roadmap 4: fuzz the parser. |
| T10 | Malicious firmware update to the signer | **Not mitigated.** Anyone with SWD access can flash new firmware. | Roadmap 2: secure bootloader that only boots signed images. |
| T11 | Supply chain of the build (CI actions, dependencies) | Partly mitigated: GitHub Actions pinned by commit SHA, Dependabot, pinned Python dependencies, read-only `GITHUB_TOKEN`. | Roadmap 3: signed releases and provenance. |
| T12 | Physical attacks (glitching, probing, decapping) | Not in scope. | A secure element (roadmap 4) raises the bar. |

## Assumptions

- The person pressing the button is authorised to approve releases.
- The enrolled public key was read from the right device (see T2a).
- The STM32 hardware RNG works as specified; its health flags and a
  continuous test are checked, but its entropy is not independently
  verified.
- SHA-256 and Ed25519 are secure.

## Explicit non-goals (for now)

- Exactly-once deployment. Single-use *acceptance* is guaranteed; whether
  the deployment that follows succeeds is the pipeline's job.
- Multi-user authorisation, roles, or quorum approvals.
- Protection of the file after `accept` (deploy from an immutable copy).
