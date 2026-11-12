# Signed Approval Protocol — Demo V1

## Scope

The host calculates a file's SHA-256 digest and sends an approval request.
STM32 firmware stores the request ID and digest, waits for a fresh button
press, and produces an Ed25519 signature after approval.
The Python client checks the response fields and verifies the signature.

Firmware receives the digest, not the file. It cannot independently
establish which file the digest represents.

## Demo key and trust

This build uses the publicly known RFC 8032 section 7.1 TEST 1 seed.
It is enabled explicitly with SIGNER_DEMO_KEY=1.

When --allow-demo-key is explicitly selected, the client uses this public key:

d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a

It does not accept a public key supplied over UART.

These are real Ed25519 signatures made with a public test key.
Anyone can reproduce them. They do not prove device identity or a real
button press and must not authorize production operations.

## Transport and framing

- UART4: PC10 TX, PC11 RX; intended configuration 115200 baud, 8N1.
- Commands are case-sensitive printable ASCII.
- Command endings: CR, LF, or CRLF.
- Response endings: CRLF.
- Empty command lines are ignored.
- Maximum command length: 127 characters, excluding the line ending.
- Command buffer: 128 bytes including the null terminator.
- Invalid and oversized lines are discarded through the next line ending.

## Request

    REQUEST <request_id> <digest>

- request_id: exactly 8 hexadecimal characters.
- digest: exactly 64 hexadecimal characters.
- Uppercase and lowercase hexadecimal letters are accepted.
- Fields use exactly one ASCII space; no leading or trailing spaces.
- Complete request length: 81 characters.
- Firmware preserves the supplied letter case.
- Only one request may be pending.
- Another request returns ERR BUSY without replacing pending data.

## Signed message

Ed25519 signs the ASCII bytes of:

    SIGNER-LAB-V1 <request_id> <digest>

The prefix and spaces are included.
There is no trailing newline or null terminator in the signed message.
The ID and digest use exactly the character case supplied in the request.

This uses ordinary Ed25519 over that message, not Ed25519ph.
The file digest is represented as hexadecimal text within the message.

## Responses

    PENDING <request_id> <digest>
    APPROVED <request_id> <digest> <signature>
    CANCELLED <request_id> <digest>
    TIMEOUT <request_id> <digest>

The signature is 64 bytes, encoded by firmware as 128 lowercase
hexadecimal characters.

Only APPROVED carries a signature.
PENDING, CANCELLED, TIMEOUT, and error responses are not authenticated.

The client rejects unsigned APPROVED responses, invalid signatures,
and responses with mismatched IDs or digests.
Direct UART mode requires PENDING before a final result and rejects
duplicate PENDING responses.

## Button approval and timeout

A valid request turns on the PD12 LED.
After the request starts, PA0 must be observed released for at least
20 ms, then pressed for at least 20 ms.

A button already held at request time must be released and pressed again.
Short pulses do not approve a request.

The approval waiting limit is 5000 ms of firmware time.
Timeout is checked before button approval in each polling iteration.
Signing and response transmission take additional time after approval.

Approval, cancellation, and timeout turn off the LED and clear pending
state and stored request fields. Processing continues without UART input.

## Other commands

| Command | Response |
| --- | --- |
| PING | PONG |
| STATUS, idle | READY |
| STATUS, pending | WAITING_APPROVAL |
| BUTTON | BUTTON PRESSED or BUTTON RELEASED |
| LED ON, idle | OK LED ON |
| LED OFF, idle | OK LED OFF |
| LED ON or LED OFF, pending | ERR BUSY |
| CANCEL, pending | CANCELLED followed by ID and digest |
| CANCEL, idle | ERR NO_PENDING_REQUEST |
| Malformed REQUEST, idle | ERR INVALID_REQUEST |
| Unknown command | ERR UNKNOWN_COMMAND |

Parser errors: ERR COMMAND_TOO_LONG and ERR INVALID_CHARACTER.

CANCEL has no ID argument and cancels the current request.
PING, STATUS, and BUTTON remain available while waiting for approval.

## Host setup and use

Install the Python dependency:

    python3 -m pip install -r requirements/host.txt

Generate a request without sending:

    python3 scripts/signer-client.py firmware/build/signer.bin

Send through a Linux PTY:

    python3 scripts/signer-client.py firmware/build/signer.bin --port /tmp/signer-uart --allow-demo-key

--request-id supplies a specific ID; otherwise a random 8-character
hexadecimal ID is generated.

--response checks a supplied response and requires --request-id.
It cannot be combined with --port.

--timeout sets the host wall-clock wait limit (default 15 seconds).
It is separate from the firmware's simulated-time timeout.
A host timeout means the firmware result is unknown and does not cancel
the pending request.

The CLI hashes the file again on each invocation.
It does not retain a request snapshot between separate invocations.

Exit codes:
- 0: request generation succeeded or signed approval was verified.
- 1: file, transport, response, or signature validation error.
- 2: matching PENDING, CANCELLED, or TIMEOUT; also argument parsing errors.

## Running Renode

    ./scripts/run-renode.sh

The launcher builds firmware and starts console-mode Renode with
UART4 exposed at /tmp/signer-uart.
RENODE_BIN can select the Renode executable.

Use another Ubuntu terminal for the Python client.
Commands such as pause, start, and quit belong in the Renode Monitor.

## Validation

    python3 -m unittest discover -s tests -p 'test_signer_*.py' -v
    ./scripts/test-crypto.sh
    ./scripts/build-firmware.sh
    ./scripts/build-crypto-test.sh
    renode-test tests/*.robot

Current coverage:
- 34 Python tests for receipts, hashing, parsing, signature verification,
  rejection cases, and PTY transport with a simulated peer.
- 18 firmware/protocol tests in tests/signer.robot.
- 2 real Python-to-Renode PTY tests in tests/direct_uart.robot.
- 1 Cortex-M4 crypto test in tests/crypto_arm.robot.
- 5 native C crypto checks run by scripts/test-crypto.sh.

The direct approval test requires successful Python Ed25519 verification.
The native and Cortex-M4 crypto tests check RFC 8032 TEST 1 and rejection
of a changed message and corrupted signature.

Monocypher 4.0.3 is vendored with its license and upstream commit.
GitHub Actions installs host dependencies, builds both firmware images,
and runs the native, Python, and Renode checks.

## Remaining limitations

- Public demo private key; no production key provisioning or protection.
- No authenticated or encrypted UART channel.
- No replay protection or enforced request ID uniqueness.
- Pending requests are lost on reset.
- No trusted display showing the requested file or digest to the user.
- Correct signatures do not establish which file was actually presented.
- Tests in Renode do not prove physical PCB operation or electrical safety.

## Approval receipts

Save a receipt after receiving and verifying a signed approval:

    python3 scripts/signer-client.py firmware/build/signer.bin --port /tmp/signer-uart --receipt-out test-results/approval.json --allow-demo-key

Create the output directory beforehand. An existing receipt is not
overwritten. A timeout or an unsigned approval does not create a receipt.

Verify the receipt against a file without connecting to Renode:

    python3 scripts/signer-client.py firmware/build/signer.bin --verify-receipt test-results/approval.json --allow-demo-key

The JSON receipt contains protocol, key_id, request_id, digest, and
signature. Verification checks the expected protocol and demo key ID,
recalculates the file's SHA-256 digest, and verifies the Ed25519 signature
using the explicitly selected trusted public key.

Offline verification does not establish freshness or prevent replay.
The public demo key does not prove device identity or a real button press.

The direct UART integration tests check receipt creation after approval,
offline verification after resetting the emulation, and absence of a
receipt after firmware timeout.

## CI demo receipt artifact

The direct approval test removes any previous exported demo receipt,
then copies the newly verified receipt to firmware/build/approval-demo.json.
The temporary UART directory is still removed during test cleanup.

GitHub Actions verifies the exported receipt against firmware/build/signer.bin
before uploading it with the firmware and test reports.

After downloading and extracting the artifact, use the matching signer.bin
and approval-demo.json paths with the host client's --verify-receipt option.

This receipt uses the public demo key and an automated simulated button press.
It demonstrates the signing pipeline; it is not a human release approval.
Artifacts can also be uploaded from failed jobs for debugging. Check the
workflow result and verify the receipt before interpreting the files.

## Explicit host trust selection

Signature verification requires an explicit trust choice:

- --allow-demo-key selects the publicly known RFC 8032 TEST 1 key.
- --public-key-file selects a trusted public key supplied by the operator.
- These options are mutually exclusive.
- Request generation alone does not require a trust choice.

The public-key file contains exactly 64 hexadecimal characters, optionally
surrounded by whitespace. It represents a raw 32-byte Ed25519 public key;
PEM is not supported. Supplying the known demo key through a file is rejected:
use --allow-demo-key explicitly.

Obtain the trusted public key through an independently trusted channel.
Neither a UART response nor a receipt can supply its own trusted key.

For non-demo keys, the receipt key_id is ED25519-SHA256- followed by the
SHA-256 fingerprint of the raw public key. This identifies the selected key;
it does not establish trust by itself.

Example verification with an operator-selected public key:

    python3 scripts/signer-client.py firmware/build/signer.bin --verify-receipt approval.json --public-key-file trusted-public-key.hex

The same selected public key is used for UART signature verification,
receipt creation, and offline receipt verification.

Firmware still supports only the public demo seed. Its build guard requires
SIGNER_DEMO_KEY=1; an undefined macro or a value of 0 is rejected.
Selecting a different host public key does not change the firmware's key.

This change adds explicit host trust configuration. It does not implement
secure private-key storage, provisioning, rotation, or replay protection.
