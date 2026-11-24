# Approval protocol (V3)

The host computes a file's SHA-256 digest and asks the device to approve
one *operation*: that digest, deployed to one target, before an expiry
time, identified by a random request ID. After a fresh press of the
physical button, the firmware takes the next value of its monotonic
approval counter and signs the operation together with that counter. The
host verifies the signature, checks that the counter is newer than the
last one it accepted from that device, then marks the operation consumed
so the same approval can never be used twice.

The firmware receives the digest, not the file. It cannot establish on its
own which file a digest represents. See [threat-model.md](threat-model.md).
The signing key is generated on the device; see
[key-management.md](key-management.md).

> Older versions were removed and answer `ERR UNKNOWN_COMMAND`:
> V1 (`REQUEST`, bound neither target nor expiry, 32-bit ID) and
> V2 (`REQUEST2`, no counter). V2 receipts do not verify with v0.4 and later.

## Transport and framing

- UART4: PC10 TX, PC11 RX, 115200 baud, 8N1.
- Reception is interrupt driven into a 512-byte ring buffer, so commands
  that arrive while a signature is computed are not lost. If the buffer
  overflows anyway, the affected line is answered with `ERR RX_OVERFLOW`.
- Commands are case-sensitive printable ASCII, terminated by CR, LF or CRLF.
- At most 255 characters per command, excluding the line ending.
- Responses end with CRLF. Empty lines are ignored.
- Invalid and oversized lines are discarded up to the next line ending.

## Operation fields

| Field | Format |
| --- | --- |
| `request_id` | 32 lowercase hex characters (128 random bits) |
| `digest` | 64 lowercase hex characters, SHA-256 of the file |
| `target` | 1–32 of `[a-z0-9_-]`; the first character is a letter or digit |
| `expires_at` | Unix time in seconds, canonical decimal (no leading zero), at most 2^53 − 1 |

The firmware has no trusted wall clock. It checks the *format* of
`expires_at` and signs it; the host enforces the actual validity period.

## Request and signed message

    REQUEST3 <request_id> <digest> <target> <expires_at>

The host does not choose the counter. On approval, the firmware stores
`counter = previous + 1` in flash and only then signs exactly these ASCII
bytes (no newline, no terminator):

    SIGNER-LAB-V3 <request_id> <digest> <target> <expires_at> <counter>

`counter` is canonical decimal, 1 to 4294967294. A reset between storing
and signing skips a number; the device never signs two approvals with the
same counter. Cancelled and timed-out requests do not use a number.

This is plain Ed25519 over the message, not Ed25519ph. The protocol
prefix separates these signatures from any other format the same key
might sign.

## Responses

    PENDING3   <request_id> <digest> <target> <expires_at>
    APPROVED3  <request_id> <digest> <target> <expires_at> <counter> <signature>
    CANCELLED3 <request_id> <digest> <target> <expires_at>
    TIMEOUT3   <request_id> <digest> <target> <expires_at>

Only `APPROVED3` is signed (128 lowercase hex characters). The other
responses are not authenticated, so the host treats them only as "not
approved".

## Button approval

- A valid request turns on the PD12 LED.
- PA0 must be seen released for 20 ms and then pressed for 20 ms. A button
  that is already held when the request arrives must be released and
  pressed again; short pulses do not approve.
- The firmware gives up after 5000 ms (`TIMEOUT3`).
- Approval, cancellation and timeout turn the LED off and wipe the stored
  request.
- Only one request can be pending; another `REQUEST3` gets `ERR BUSY` and
  does not replace it.

## Other commands

| Command | Response |
| --- | --- |
| `PING` | `PONG` |
| `STATUS` | `READY`, or `WAITING_APPROVAL` while pending |
| `BUTTON` | `BUTTON PRESSED` or `BUTTON RELEASED` |
| `LED ON` / `LED OFF` | `OK LED ON` / `OK LED OFF`; `ERR BUSY` while pending |
| `CANCEL` | `CANCELLED3 ...`, or `ERR NO_PENDING_REQUEST` |
| `PUBKEY` | `PUBKEY <64 hex>`, or `ERR NO_KEY` |
| `COUNTER` | `COUNTER <n>`: last counter value used (0 before the first approval) |
| `REQUEST3` without a valid key | `ERR NO_KEY` |
| malformed `REQUEST3` | `ERR INVALID_REQUEST` |
| approval when the counter cannot be stored | `ERR COUNTER_FAILURE` (nothing is signed) |
| anything else | `ERR UNKNOWN_COMMAND` |

Parser errors: `ERR COMMAND_TOO_LONG`, `ERR INVALID_CHARACTER`,
`ERR RX_OVERFLOW`.

## Device health lines

These can appear at any time and are not answers to a command:

| Line | Meaning |
| --- | --- |
| `Signer firmware started` | Boot finished. |
| `INFO KEY_GENERATED` / `INFO KEY_LOADED` | Key store state at boot. |
| `INFO COUNTER <n>` | Counter value found in flash at boot. |
| `WARN KEY_CORRUPT`, `WARN RNG_FAILURE`, `WARN FLASH_WRITE_FAILED`, `WARN KEY_GENERATION_FAILED` | No usable key; signing is refused. |
| `WARN WATCHDOG_RESET` | The previous run ended in a watchdog reset (real hardware; Renode does not model the reset flags). |
| `FAULT pc=… lr=… cfsr=… hfsr=… bfar=…` | A CPU fault occurred. The LED blinks rapidly and the watchdog resets the device about 4 s later. |

The host client skips `INFO`/`WARN` lines and the start line, and aborts
the exchange on `FAULT`.

## Host side

```
signer-lab enroll  --port P --key-out KEY            # store the device public key once
signer-lab request FILE --target T                   # print a REQUEST3 line
signer-lab approve FILE --port P --database DB --target T [--receipt-out R] --public-key-file KEY
signer-lab accept  FILE --receipt R --database DB --target T --public-key-file KEY
signer-lab verify  FILE --receipt R [--target T] --public-key-file KEY
```

`approve` registers the operation in SQLite (with the trusted key), sends
`REQUEST3`, waits for `PENDING3` and the final response, verifies the
signature, re-hashes the file, consumes the operation and optionally
writes a receipt. Exit codes: 0 accepted, 2 not approved (timeout or
cancel), 1 error.

`accept` consumes a registered operation using a receipt. A second
`accept` of the same receipt fails with "already consumed", also across
processes and restarts; concurrent consumers are serialised by SQLite.

Consumption also requires the approval's counter to be larger than the
highest counter already accepted from the same device key ("not newer"
otherwise). The counter and the high-water mark are stored with the
approval in the same transaction.

`verify` checks a receipt offline: signature, file digest and optionally
the target. It does **not** prove that the approval is unused.

### Receipt format

```json
{
  "protocol": "SIGNER-LAB-V3",
  "key_id": "ED25519-SHA256-<64 hex>",
  "request_id": "<32 hex>",
  "digest": "<64 hex>",
  "target": "staging",
  "expires_at": 1800000000,
  "counter": 17,
  "signature": "<128 hex>"
}
```

Unknown, missing or duplicated fields are rejected. `key_id` is
`ED25519-SHA256-` followed by the SHA-256 of the device public key.

## Limits

- Protect the database and the host clock: rolling back or editing the
  database undermines single use, and restores an old counter high-water
  mark with it (see threat T7).
- Single-use acceptance is not exactly-once deployment. If writing the
  receipt fails after consumption, the operation stays consumed.
- The file is re-hashed before consumption, but nothing stops it from
  changing afterwards; deploy from an immutable copy.
- Old database schemas (before V3) are rejected instead of being migrated
  silently; start a new database file.
