#!/usr/bin/env python3
"""Demo V2 UART approval and persistent single-use acceptance."""

import argparse
import importlib.util
import math
from pathlib import Path
import re
import secrets
import sqlite3
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from approval_store import ApprovalStore
from signer_key_policy import load_trusted_key
from signer_protocol_v2 import approval_message, build_request, validate_fields

SPEC = importlib.util.spec_from_file_location(
    "signer_v1_transport", Path(__file__).with_name("signer-client.py")
)
transport = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(transport)


def parse_response(line):
    if line.endswith("\r\n"):
        line = line[:-2]
    elif line.endswith("\n") or line.endswith("\r"):
        line = line[:-1]

    parts = line.split(" ")
    if not parts or parts[0] not in (
        "PENDING2", "APPROVED2", "CANCELLED2", "TIMEOUT2"
    ):
        raise ValueError("Invalid V2 response type.")

    status = parts[0]
    if len(parts) != (6 if status == "APPROVED2" else 5):
        raise ValueError("Invalid V2 response field count.")

    request_id, digest, target, expiry_text = parts[1:5]
    if re.fullmatch(r"[1-9][0-9]{0,15}", expiry_text) is None:
        raise ValueError("Invalid canonical expiry.")
    expiry = int(expiry_text)
    validate_fields(request_id, digest, target, expiry)

    signature = None
    if status == "APPROVED2":
        if re.fullmatch(r"[0-9a-f]{128}", parts[5]) is None:
            raise ValueError("Invalid V2 signature encoding.")
        signature = bytes.fromhex(parts[5])

    return status, request_id, digest, target, expiry, signature


def checked_response(line, expected, trusted_key):
    parsed = parse_response(line)
    status, request_id, digest, target, expiry, signature = parsed
    if (request_id, digest, target, expiry) != expected:
        raise ValueError("V2 response does not match the expected operation.")

    if status == "APPROVED2":
        try:
            Ed25519PublicKey.from_public_bytes(trusted_key).verify(
                signature, approval_message(request_id, digest, target, expiry)
            )
        except InvalidSignature as error:
            raise ValueError("Invalid V2 signature.") from error
    return parsed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file", type=Path)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--request-id")
    parser.add_argument("--ttl", type=int, default=300)
    parser.add_argument("--timeout", type=float, default=60)
    parser.add_argument("--response-out", type=Path)

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--port")
    mode.add_argument("--accept-response", type=Path)

    trust = parser.add_mutually_exclusive_group(required=True)
    trust.add_argument("--allow-demo-key", action="store_true")
    trust.add_argument("--public-key-file", type=Path)
    args = parser.parse_args()

    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("--timeout must be finite and positive.")
    if not 1 <= args.ttl <= 86400:
        parser.error("--ttl must be between 1 and 86400 seconds.")
    if args.accept_response and (not args.request_id or args.response_out):
        parser.error("--accept-response requires --request-id and forbids --response-out.")

    try:
        key = load_trusted_key(args.public_key_file, args.allow_demo_key)
        digest = transport.sha256_file(args.file)
        request_id = args.request_id or secrets.token_hex(16)

        if args.accept_response:
            line = args.accept_response.read_text(encoding="ascii")
            parsed = parse_response(line)
            if parsed[0] != "APPROVED2":
                raise ValueError("Only APPROVED2 can be accepted.")
            expiry = parsed[4]
            expected = (request_id, digest, args.target, expiry)
            parsed = checked_response(line, expected, key)
            store = ApprovalStore(args.database)
        else:
            now = time.time()
            expiry = int(now) + args.ttl
            expected = (request_id, digest, args.target, expiry)
            command = build_request(*expected)
            store = ApprovalStore(args.database)

            # Exclusive creation prevents overwriting an existing response file.
            # Check before sending, but use exclusive creation again when writing.
            if args.response_out and args.response_out.exists():
                raise FileExistsError("Response output already exists.")

            store.register(
                request_id, digest, args.target,
                trusted_key=key, now=now, expires_at=expiry,
            )

            def validate_line(response):
                status = checked_response(response, expected, key)[0]
                return status[:-1]

            line = transport.exchange_command(
                args.port, command, args.timeout, validate_line,
                max_line=512,
            )
            parsed = checked_response(line, expected, key)
            if parsed[0] != "APPROVED2":
                print(f"NOT ACCEPTED: {parsed[0]}")
                return 2

        # Refuse to consume if the input file changed while waiting.
        if transport.sha256_file(args.file) != digest:
            raise ValueError("File changed during approval.")

        store.consume(
            request_id, digest, args.target,
            expires_at=expiry, signature=parsed[5],
        )

        if args.response_out:
            with args.response_out.open("x", encoding="ascii") as output:
                output.write(line.rstrip("\r\n") + "\n")

        print(f"ACCEPTED2 {request_id} {digest} {args.target}")
        return 0

    except (OSError, ValueError, sqlite3.Error) as error:
        parser.exit(1, f"Hata: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
