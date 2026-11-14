"""Shared test helpers. Importing this module makes `signer_lab` importable
from a checkout without installing it."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "host") not in sys.path:
    sys.path.insert(0, str(ROOT / "host"))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

# RFC 8032 TEST 1 seed. Public test data, never a production secret.
DEMO_SEED = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc4"
    "4449c5697b326919703bac031cae7f60"
)


def demo_private_key():
    return Ed25519PrivateKey.from_private_bytes(DEMO_SEED)


def raw_public_key(private_key):
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def fields_text(fields):
    return " ".join(map(str, fields))


def signed_line(private_key, fields):
    """APPROVED2 line built independently of signer_lab's message helper."""
    message = ("SIGNER-LAB-V2 " + fields_text(fields)).encode("ascii")
    return f"APPROVED2 {fields_text(fields)} {private_key.sign(message).hex()}"
