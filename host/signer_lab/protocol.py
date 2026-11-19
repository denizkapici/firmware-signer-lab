"""Canonical V2 wire format: request line, signed message, responses."""

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PROTOCOL = "SIGNER-LAB-V2"
MAX_EXPIRY = 2**53 - 1

REQUEST_ID_PATTERN = re.compile(r"[0-9a-f]{32}")
DIGEST_PATTERN = re.compile(r"[0-9a-f]{64}")
TARGET_PATTERN = re.compile(r"[a-z0-9][a-z0-9_-]{0,31}")
EXPIRY_PATTERN = re.compile(r"[1-9][0-9]{0,15}")
SIGNATURE_PATTERN = re.compile(r"[0-9a-f]{128}")

STATUSES = ("PENDING2", "APPROVED2", "CANCELLED2", "TIMEOUT2")


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_fields(request_id, digest, target, expires_at):
    if not isinstance(request_id, str) or not REQUEST_ID_PATTERN.fullmatch(request_id):
        raise ValueError("Request ID must be 32 lowercase hex characters.")
    if not isinstance(digest, str) or not DIGEST_PATTERN.fullmatch(digest):
        raise ValueError("Digest must be 64 lowercase hex characters.")
    if not isinstance(target, str) or not TARGET_PATTERN.fullmatch(target):
        raise ValueError("Invalid target.")
    if (
        isinstance(expires_at, bool)
        or not isinstance(expires_at, int)
        or not 1 <= expires_at <= MAX_EXPIRY
    ):
        raise ValueError("Expiry must be a positive integer Unix timestamp.")


def encoded_fields(request_id, digest, target, expires_at):
    validate_fields(request_id, digest, target, expires_at)
    return f"{request_id} {digest} {target} {expires_at}"


def build_request(request_id, digest, target, expires_at):
    return "REQUEST2 " + encoded_fields(request_id, digest, target, expires_at)


def approval_message(request_id, digest, target, expires_at):
    """Exact bytes signed by the firmware (no newline, no terminator)."""
    fields = encoded_fields(request_id, digest, target, expires_at)
    return f"{PROTOCOL} {fields}".encode("ascii")


@dataclass(frozen=True)
class Operation:
    """The four fields an approval is bound to."""

    request_id: str
    digest: str
    target: str
    expires_at: int

    def __post_init__(self):
        validate_fields(self.request_id, self.digest, self.target, self.expires_at)

    def request_line(self):
        return build_request(self.request_id, self.digest, self.target, self.expires_at)

    def message(self):
        return approval_message(self.request_id, self.digest, self.target, self.expires_at)


@dataclass(frozen=True)
class Response:
    status: str
    operation: Operation
    signature: bytes | None = None


def parse_response(line):
    """Parse one firmware response line. Does not check the signature."""
    if line.endswith("\r\n"):
        line = line[:-2]
    elif line.endswith("\n") or line.endswith("\r"):
        line = line[:-1]

    parts = line.split(" ")
    status = parts[0]
    if status not in STATUSES:
        raise ValueError("Invalid V2 response type.")
    if len(parts) != (6 if status == "APPROVED2" else 5):
        raise ValueError("Invalid V2 response field count.")

    request_id, digest, target, expiry_text = parts[1:5]
    if EXPIRY_PATTERN.fullmatch(expiry_text) is None:
        raise ValueError("Invalid canonical expiry.")
    operation = Operation(request_id, digest, target, int(expiry_text))

    signature = None
    if status == "APPROVED2":
        if SIGNATURE_PATTERN.fullmatch(parts[5]) is None:
            raise ValueError("Invalid V2 signature encoding.")
        signature = bytes.fromhex(parts[5])

    return Response(status, operation, signature)


def verify_signature(operation, signature, trusted_key):
    try:
        Ed25519PublicKey.from_public_bytes(trusted_key).verify(
            signature, operation.message()
        )
    except InvalidSignature as error:
        raise ValueError("Invalid V2 signature.") from error


def check_response(line, expected, trusted_key):
    """Parse a response, require it to match `expected`, verify APPROVED2."""
    response = parse_response(line)
    if response.operation != expected:
        raise ValueError("V2 response does not match the expected operation.")
    if response.status == "APPROVED2":
        verify_signature(response.operation, response.signature, trusted_key)
    return response
