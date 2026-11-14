"""Approval receipts: a signed APPROVED2 response stored as JSON.

A receipt proves that a device holding the trusted key approved exactly
this operation. It can be verified offline any number of times; it does
not prove that the approval has not been used already. Single use is
enforced by ApprovalStore.consume().
"""

import json
from pathlib import Path

from .keys import key_id
from .protocol import (
    PROTOCOL,
    SIGNATURE_PATTERN,
    Operation,
    Response,
    sha256_file,
    verify_signature,
)

FIELDS = {"protocol", "key_id", "request_id", "digest", "target", "expires_at", "signature"}


def save_receipt(path, response, *, trusted_key):
    if response.status != "APPROVED2" or response.signature is None:
        raise ValueError("Only a signed APPROVED2 response can be saved.")
    verify_signature(response.operation, response.signature, trusted_key)

    operation = response.operation
    receipt = {
        "protocol": PROTOCOL,
        "key_id": key_id(trusted_key),
        "request_id": operation.request_id,
        "digest": operation.digest,
        "target": operation.target,
        "expires_at": operation.expires_at,
        "signature": response.signature.hex(),
    }

    # Exclusive creation: never overwrite an existing receipt.
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(receipt, stream, indent=2)
        stream.write("\n")


def _unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Receipt contains a duplicate field.")
        result[key] = value
    return result


def load_receipt(receipt_path, *, trusted_key):
    """Parse a receipt and verify its signature. Returns a Response."""
    with Path(receipt_path).open("r", encoding="utf-8") as stream:
        receipt = json.load(stream, object_pairs_hook=_unique_fields)

    if not isinstance(receipt, dict) or set(receipt) != FIELDS:
        raise ValueError("Receipt fields are invalid.")
    if receipt["protocol"] != PROTOCOL:
        raise ValueError("Unsupported receipt protocol.")
    if receipt["key_id"] != key_id(trusted_key):
        raise ValueError("Receipt was not signed by the trusted key.")

    signature = receipt["signature"]
    if not isinstance(signature, str) or SIGNATURE_PATTERN.fullmatch(signature) is None:
        raise ValueError("Receipt signature encoding is invalid.")

    operation = Operation(
        receipt["request_id"], receipt["digest"], receipt["target"], receipt["expires_at"]
    )
    response = Response("APPROVED2", operation, bytes.fromhex(signature))
    verify_signature(operation, response.signature, trusted_key)
    return response


def verify_receipt(file_path, receipt_path, *, trusted_key, target=None):
    """Offline check: signature, file digest and (optionally) target."""
    response = load_receipt(receipt_path, trusted_key=trusted_key)
    if sha256_file(file_path) != response.operation.digest:
        raise ValueError("File digest does not match the receipt.")
    if target is not None and target != response.operation.target:
        raise ValueError("Receipt was issued for another target.")
    return response
