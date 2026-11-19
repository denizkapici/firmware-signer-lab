"""Trusted device public keys. Contains no private keys."""

import hashlib
import re
from pathlib import Path

# RFC 8032 section 7.1, TEST 1. Its private key is published, so a device
# or key file presenting it is never trusted.
DEMO_PUBLIC_KEY = bytes.fromhex(
    "d75a980182b10ab7d54bfed3c964073a"
    "0ee172f3daa62325af021a68f707511a"
)

PUBLIC_KEY_PATTERN = re.compile(r"[0-9a-fA-F]{64}")


def parse_public_key(text):
    """Parse 64 hex characters into a 32-byte Ed25519 public key."""
    text = text.strip()
    if PUBLIC_KEY_PATTERN.fullmatch(text) is None:
        raise ValueError("A public key must be 64 hex characters.")

    public_key = bytes.fromhex(text)
    if public_key == DEMO_PUBLIC_KEY:
        raise ValueError("Refusing the public RFC 8032 test key.")
    if public_key == bytes(32) or public_key == b"\xff" * 32:
        raise ValueError("Public key is blank.")
    return public_key


def load_trusted_key(public_key_file):
    if public_key_file is None:
        raise ValueError("A trusted public key file is required.")
    return parse_public_key(Path(public_key_file).read_text(encoding="ascii"))


def save_public_key(path, public_key):
    """Write an enrolled key. Never overwrites an existing file."""
    with Path(path).open("x", encoding="ascii") as stream:
        stream.write(public_key.hex() + "\n")


def key_id(public_key):
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes.")
    return "ED25519-SHA256-" + hashlib.sha256(public_key).hexdigest()
