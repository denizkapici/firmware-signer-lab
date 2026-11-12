# Single-use approval — V2 demo

## Scope

V2 binds an approval to a request ID, file digest, target, and expiry.
The host verifies the signature using the public key pinned in the
registered operation, then atomically marks the operation consumed.

This is a demo using a publicly known private key. It does not establish
device identity or trustworthy human approval and does not perform deployment.

## Protocol

Request:

    REQUEST2 <request_id> <digest> <target> <expires_at>

Signed ASCII message, without newline or null terminator:

    SIGNER-LAB-V2 <request_id> <digest> <target> <expires_at>

Fields:

- request_id: 32 lowercase hexadecimal characters.
- digest: 64 lowercase hexadecimal characters, SHA-256 of the file.
- target: 1–32 lowercase ASCII letters, digits, underscores or hyphens;
  the first character must be a letter or digit.
- expires_at: positive Unix timestamp in seconds, canonical decimal,
  no leading zeros, maximum 9007199254740991.

Responses:

    PENDING2 <request_id> <digest> <target> <expires_at>
    APPROVED2 <request_id> <digest> <target> <expires_at> <signature>
    CANCELLED2 <request_id> <digest> <target> <expires_at>
    TIMEOUT2 <request_id> <digest> <target> <expires_at>

Only APPROVED2 is signed. The signature is 128 lowercase hex characters.

Firmware retains the separate five-second button approval timeout.
The host checks the signed Unix expiry; firmware does not have a trusted
wall clock and does not enforce that expiry.

V1 remains supported with its 127-character command limit.
Commands beginning with "REQUEST2 " may contain up to 255 characters,
excluding the line ending.

## Host usage

Activate the Python environment with requirements/host.txt installed.
Start Renode in another terminal:

    ./scripts/run-renode.sh

From the project root, create a persistent local state directory:

    mkdir -p ~/.local/state/firmware-signer-lab

Request approval:

    python3 scripts/signer-v2.py firmware/build/signer.bin \
      --database ~/.local/state/firmware-signer-lab/approvals.sqlite3 \
      --target staging \
      --port /tmp/signer-uart \
      --allow-demo-key \
      --timeout 120 \
      --ttl 300

The client generates a random 128-bit request ID unless --request-id is given.
The selected trusted public key is stored when registering the operation.

--timeout is the host UART wait limit in wall-clock seconds.
--ttl sets the operation lifetime in wall-clock seconds (1–86400).
Neither changes the firmware's five-second simulated button timeout.

A fresh release and press of the simulated button is required.
For controlled manual testing, pause Renode before sending the request
and advance it using RunFor. RunFor requires paused emulation.

## Acceptance and replay

Acceptance checks the signature, request ID, digest, target, expiry,
pending state, and validity period before consuming the record.

Competing consumers are serialized in SQLite; only one succeeds.
Consumed records remain consumed across process restarts.

--response-out saves the accepted raw APPROVED2 line to a new file.
It is not the V1 JSON receipt format. Existing output files are not overwritten.

--accept-response accepts a saved line against an existing operation.
It requires --request-id, --target, --database, and explicit trust selection.
It does not register a new operation. Reusing an already consumed approval fails.

A firmware timeout or cancellation does not consume the host record.
The record remains pending until its host expiry prevents acceptance.
Nonapproval responses are not authenticated.

## Limits and failure behavior

- Protect the database and host clock. Database rollback or alteration can
  undermine the single-use guarantee.
- The public demo private key allows anyone to forge demo signatures.
- The CLI is a local lab tool, not a multi-user authorization service.
- If output writing fails after consumption, the record remains consumed.
- A crash after consumption does not automatically retry or perform deployment.
- Single-use acceptance is not an exactly-once deployment guarantee.
- Files are rehashed before consumption, but this does not provide an immutable
  deployment artifact or prevent changes after that check.
- Old database schemas are rejected rather than silently migrated.
- Firmware V2 and the SQLite mechanism do not protect the V1 workflow from replay.

## Validation

The test suite includes:

- 62 Python tests covering protocol, key policy, signatures, state, and clients.
- 23 firmware/protocol tests in tests/signer.robot.
- 4 direct UART integration tests in tests/direct_uart.robot.
- 1 Cortex-M4 crypto test in tests/crypto_arm.robot.

The V2 direct integration test obtains a real Renode UART signature,
accepts it once, and rejects reuse in a separate Python process.
The timeout test confirms that no accepted response file is produced and
the database record remains pending with no consumption timestamp.
