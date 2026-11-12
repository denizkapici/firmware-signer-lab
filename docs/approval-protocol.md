# Approval Protocol

## Scope

This project implements a simulated button-controlled approval workflow.
The host calculates a file's SHA-256 digest. Firmware stores the supplied
request ID and digest, waits for button approval, and returns a result.

The firmware does not receive the file, calculate its hash, or generate
a cryptographic signature. An APPROVED response is a protocol message,
not cryptographic proof of approval or device identity.

## Transport and framing

- Firmware UART: UART4, PC10 TX and PC11 RX.
- Intended configuration: 115200 baud, 8 data bits, no parity, 1 stop bit.
- Commands are case-sensitive printable ASCII.
- Commands may end with CR, LF, or CRLF.
- Responses end with CRLF.
- Empty command lines are ignored.
- Maximum command length: 127 characters, excluding the line ending.
- The command buffer is 128 bytes, including the null terminator.
- Invalid or oversized lines are discarded until the next line ending.
- The next command can then be processed normally.

## Request format

REQUEST <request_id> <digest>

- request_id: exactly 8 hexadecimal characters.
- digest: exactly 64 hexadecimal characters.
- Uppercase and lowercase hexadecimal characters are accepted.
- Fields must be separated by exactly one ASCII space.
- Leading or trailing spaces are not accepted.
- A complete REQUEST command is 81 characters long.
- Firmware preserves the supplied hexadecimal letter case in responses.

Example using the SHA-256 digest of the three bytes abc:

REQUEST A0000001 ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad

Only one request may be pending. A second request is rejected with
ERR BUSY and cannot replace the pending request ID or digest.

## Approval lifecycle

1. A valid REQUEST stores its ID and digest, lights PD12, and returns:
   PENDING <request_id> <digest>
2. After the request begins, PA0 must be observed released for at least
   20 ms before approval is armed.
3. PA0 must then be observed pressed for at least 20 ms.
4. A successful approval returns:
   APPROVED <request_id> <digest>
5. If the request reaches 5000 ms without approval, firmware returns:
   TIMEOUT <request_id> <digest>
6. CANCEL ends a pending request and returns:
   CANCELLED <request_id> <digest>

Approval, cancellation, and timeout turn off the LED and clear the
pending state and stored request fields.

A button already held when a request starts cannot approve it.
It must be released and pressed again.

Button handling and timeout processing continue without incoming UART
commands. SysTick provides the millisecond counter. Firmware checks
timeout before checking button approval in each polling iteration.

## Commands and responses

| Command | Response |
| --- | --- |
| PING | PONG |
| STATUS, no pending request | READY |
| STATUS, request pending | WAITING_APPROVAL |
| BUTTON | BUTTON PRESSED or BUTTON RELEASED |
| LED ON, no pending request | OK LED ON |
| LED OFF, no pending request | OK LED OFF |
| LED ON or LED OFF, request pending | ERR BUSY |
| Valid REQUEST, no pending request | PENDING followed by ID and digest |
| REQUEST while a request is pending | ERR BUSY |
| Malformed REQUEST, no pending request | ERR INVALID_REQUEST |
| CANCEL, request pending | CANCELLED followed by ID and digest |
| CANCEL, no pending request | ERR NO_PENDING_REQUEST |
| Unknown command | ERR UNKNOWN_COMMAND |

Parser errors:

- ERR COMMAND_TOO_LONG
- ERR INVALID_CHARACTER

CANCEL has no request ID argument and cancels the current pending request.
PING, STATUS, and BUTTON remain available while approval is pending.
Debug LED commands do not modify the LED while approval is pending.

## Python host client

Generate a request for a file:

    python3 scripts/signer-client.py firmware/build/signer.bin --request-id A0000001

If --request-id is omitted, the client generates an 8-character
hexadecimal ID.

The client can also check a supplied response using --response.
When --response is used, --request-id is required.

Response validation requires an exact match of both the request ID and
digest, including letter case.

Exit codes:

- 0: request generation succeeded, or a matching APPROVED was validated.
- 1: file access or response validation failed.
- 2: a matching PENDING, CANCELLED, or TIMEOUT was received.
  Argument parsing errors also use exit code 2.

The CLI supports direct Linux PTY communication through --port:

    python3 scripts/signer-client.py firmware/build/signer.bin --port /tmp/signer-uart

The client sends a request, validates the matching PENDING response,
and waits for a matching APPROVED, CANCELLED, or TIMEOUT response.
It rejects mismatched IDs or digests and unexpected response sequences.

--timeout sets the host's wall-clock waiting limit (default: 15 seconds).
The firmware's 5000 ms timeout uses simulated time. These are separate
limits. A host timeout means the firmware outcome is unknown; it does
not cancel the pending firmware request.

Direct PTY timeout and approval paths are covered by
tests/direct_uart.robot. Robot Framework controls simulated time and
the button, while the real Python client communicates over the PTY.
The original tests/signer.robot suite also tests firmware behavior
using Robot Framework UART keywords.
For response checking, the CLI hashes the file again; it does not retain
a request snapshot between separate invocations.

## Validation

Run host tests:

    python3 -m unittest discover -s tests -p 'test_signer_*.py' -v

Build firmware:

    ./scripts/build-firmware.sh

Run Renode tests with the installed Renode test runner:

    renode-test tests/*.robot

The current suite contains 13 Python tests and 20 Renode tests.

Coverage includes command boundaries, invalid input, timer operation,
fresh button approval, held-button rejection, short-pulse rejection,
cancellation, timeout, malformed requests, pending digest preservation,
and a request generated from a real file by the Python client.

GitHub Actions runs the host tests, firmware build, and Renode tests.

## Current limitations

- No cryptographic signing or signature verification.
- No authenticated or encrypted UART protocol.
- No replay protection or enforced request ID uniqueness.
- Pending requests are stored in RAM and are lost on reset.
- The button provides physical approval but there is no trusted display
  showing the file or digest to the person pressing it.
- A syntactically valid digest is accepted; firmware cannot establish
  whether it corresponds to any particular file.
- Unit tests validate the Python response checker separately.
  Direct integration tests additionally exercise the actual Python
  client against Renode through a Linux PTY.
- Renode tests validate modeled firmware behavior. They do not prove
  physical PCB operation, electrical integrity, or real button behavior.

## Automated PTY transport tests

Five Python tests use temporary Linux PTYs with a simulated peer.
They cover fragmented approval responses, mismatched digests,
final results without PENDING, duplicate PENDING responses,
and host timeout when the peer is silent.

These five tests exercise the Python transport without Renode.
Two additional tests in tests/direct_uart.robot exercise the actual
Python client against Renode and check approval and firmware timeout.
They verify matching response fields and client exit codes.
