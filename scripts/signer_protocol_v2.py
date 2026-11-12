"""Canonical V2 request and signed-message encoding."""

import re

PROTOCOL = "SIGNER-LAB-V2"


def validate_fields(request_id, digest, target, expires_at):
    if not isinstance(request_id, str) or not re.fullmatch(
        r"[0-9a-f]{32}", request_id
    ):
        raise ValueError("V2 request ID must be 32 lowercase hex characters.")

    if not isinstance(digest, str) or not re.fullmatch(
        r"[0-9a-f]{64}", digest
    ):
        raise ValueError("V2 digest must be 64 lowercase hex characters.")

    if not isinstance(target, str) or not re.fullmatch(
        r"[a-z0-9][a-z0-9_-]{0,31}", target
    ):
        raise ValueError("Invalid V2 target.")

    if (
        isinstance(expires_at, bool)
        or not isinstance(expires_at, int)
        or not 1 <= expires_at <= 9007199254740991
    ):
        raise ValueError("Expiry must be a positive integer Unix timestamp.")


def encoded_fields(request_id, digest, target, expires_at):
    validate_fields(request_id, digest, target, expires_at)
    return f"{request_id} {digest} {target} {expires_at}"


def build_request(request_id, digest, target, expires_at):
    fields = encoded_fields(request_id, digest, target, expires_at)
    return f"REQUEST2 {fields}"


def approval_message(request_id, digest, target, expires_at):
    fields = encoded_fields(request_id, digest, target, expires_at)
    return f"{PROTOCOL} {fields}".encode("ascii")
