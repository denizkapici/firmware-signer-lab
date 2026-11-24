"""Command line interface: python -m signer_lab <command> ..."""

import argparse
import math
import secrets
import sqlite3
import sys
import time
from pathlib import Path

from .keys import key_id, load_trusted_key, parse_public_key, save_public_key
from .protocol import Operation, check_response, sha256_file
from .receipt import load_receipt, save_receipt, verify_receipt
from .store import ApprovalStore
from .transport import TransportError, exchange_command, query

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_NOT_APPROVED = 2


def add_trust_options(parser):
    parser.add_argument(
        "--public-key-file", type=Path, required=True,
        help="enrolled device public key (from 'signer-lab enroll')",
    )


def trusted_key(args):
    return load_trusted_key(args.public_key_file)


def new_operation(file, target, request_id, ttl, now):
    return Operation(
        request_id or secrets.token_hex(16),
        sha256_file(file),
        target,
        int(now) + ttl,
    )


def command_enroll(args):
    """Read the device public key once and store it as the trusted key."""
    if args.key_out.exists():
        raise FileExistsError(f"Key file already exists: {args.key_out}")

    line = query(args.port, "PUBKEY", args.timeout).rstrip("\r\n")
    parts = line.split(" ")
    if len(parts) != 2 or parts[0] != "PUBKEY":
        raise TransportError(f"Unexpected answer to PUBKEY: {line!r}")

    public_key = parse_public_key(parts[1])
    save_public_key(args.key_out, public_key)
    print(f"ENROLLED {key_id(public_key)}")
    print(f"Public key saved: {args.key_out}")
    print("Check this key ID against the device before trusting it.")
    return EXIT_OK


def command_request(args):
    """Print the REQUEST3 line for manual use (no state is recorded)."""
    operation = new_operation(args.file, args.target, args.request_id, args.ttl, time.time())
    print(operation.request_line())
    return EXIT_OK


def command_approve(args):
    """Register, ask the device, verify, consume, and save a receipt."""
    key = trusted_key(args)
    if args.receipt_out is not None and args.receipt_out.exists():
        raise FileExistsError(f"Receipt already exists: {args.receipt_out}")

    now = time.time()
    operation = new_operation(args.file, args.target, args.request_id, args.ttl, now)
    store = ApprovalStore(args.database)
    store.register(
        operation.request_id, operation.digest, operation.target,
        trusted_key=key, now=now, expires_at=operation.expires_at,
    )

    def classify(line):
        status = check_response(line, operation, key).status
        return "PENDING" if status == "PENDING3" else status

    line = exchange_command(args.port, operation.request_line(), args.timeout, classify)
    response = check_response(line, operation, key)
    if response.status != "APPROVED3":
        print(f"NOT ACCEPTED: {response.status}")
        return EXIT_NOT_APPROVED

    # Refuse to consume if the file changed while waiting for the button.
    if sha256_file(args.file) != operation.digest:
        raise ValueError("File changed during approval.")

    store.consume(
        operation.request_id, operation.digest, operation.target,
        expires_at=operation.expires_at, counter=response.counter,
        signature=response.signature,
    )
    if args.receipt_out is not None:
        save_receipt(args.receipt_out, response, trusted_key=key)
        print(f"Receipt saved: {args.receipt_out}")

    print(
        f"ACCEPTED3 {operation.request_id} {operation.digest} {operation.target} "
        f"counter={response.counter}"
    )
    print(f"Ed25519 signature verified with {key_id(key)}.")
    return EXIT_OK


def command_accept(args):
    """Consume a registered approval using a receipt (single use)."""
    key = trusted_key(args)
    response = load_receipt(args.receipt, trusted_key=key)
    operation = response.operation

    if operation.target != args.target:
        raise ValueError("Receipt was issued for another target.")
    if sha256_file(args.file) != operation.digest:
        raise ValueError("File digest does not match the receipt.")

    ApprovalStore(args.database).consume(
        operation.request_id, operation.digest, operation.target,
        expires_at=operation.expires_at, counter=response.counter,
        signature=response.signature,
    )
    print(
        f"ACCEPTED3 {operation.request_id} {operation.digest} {operation.target} "
        f"counter={response.counter}"
    )
    return EXIT_OK


def command_verify(args):
    """Offline check of a receipt. Does not consume anything."""
    key = trusted_key(args)
    response = verify_receipt(args.file, args.receipt, trusted_key=key, target=args.target)
    operation = response.operation
    print(
        f"VALID {operation.request_id} {operation.digest} {operation.target} "
        f"{operation.expires_at} counter={response.counter}"
    )
    print(f"File digest and Ed25519 signature verified with {key_id(key)}.")
    print("Note: this does not prove the approval is unused; use 'accept' for that.")
    return EXIT_OK


def positive_finite(text):
    value = float(text)
    if not math.isfinite(value) or value <= 0:
        raise argparse.ArgumentTypeError("must be finite and positive")
    return value


def ttl_seconds(text):
    value = int(text)
    if not 1 <= value <= 86400:
        raise argparse.ArgumentTypeError("must be between 1 and 86400 seconds")
    return value


def build_parser():
    parser = argparse.ArgumentParser(
        prog="signer-lab",
        description="Host client for the button-approved firmware signer.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    enroll = commands.add_parser("enroll", help="store the device public key (first use)")
    enroll.add_argument("--port", required=True, help="serial/PTY path, e.g. /tmp/signer-uart")
    enroll.add_argument("--key-out", type=Path, required=True)
    enroll.add_argument("--timeout", type=positive_finite, default=10.0)
    enroll.set_defaults(handler=command_enroll)

    request = commands.add_parser("request", help="print a REQUEST3 line for a file")
    request.add_argument("file", type=Path)
    request.add_argument("--target", required=True)
    request.add_argument("--request-id")
    request.add_argument("--ttl", type=ttl_seconds, default=300)
    request.set_defaults(handler=command_request)

    approve = commands.add_parser("approve", help="request device approval for a file")
    approve.add_argument("file", type=Path)
    approve.add_argument("--port", required=True, help="serial/PTY path, e.g. /tmp/signer-uart")
    approve.add_argument("--database", type=Path, required=True)
    approve.add_argument("--target", required=True)
    approve.add_argument("--request-id")
    approve.add_argument("--ttl", type=ttl_seconds, default=300)
    approve.add_argument("--timeout", type=positive_finite, default=60.0)
    approve.add_argument("--receipt-out", type=Path)
    add_trust_options(approve)
    approve.set_defaults(handler=command_approve)

    accept = commands.add_parser("accept", help="consume an approval receipt once")
    accept.add_argument("file", type=Path)
    accept.add_argument("--receipt", type=Path, required=True)
    accept.add_argument("--database", type=Path, required=True)
    accept.add_argument("--target", required=True)
    add_trust_options(accept)
    accept.set_defaults(handler=command_accept)

    verify = commands.add_parser("verify", help="verify a receipt offline")
    verify.add_argument("file", type=Path)
    verify.add_argument("--receipt", type=Path, required=True)
    verify.add_argument("--target")
    add_trust_options(verify)
    verify.set_defaults(handler=command_verify)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except (OSError, ValueError, sqlite3.Error) as error:
        print(f"Error: {error}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
