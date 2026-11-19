"""Verify an APPROVED2 signature with a device public key (independent of
the signer_lab package). Exit status 0 only for a valid signature."""

import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

DEMO_PUBLIC_KEY = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

if len(sys.argv) != 7:
    raise SystemExit("Expected: public_key request_id digest target expires_at signature")

public_key, *fields, signature = sys.argv[1:]
if public_key == DEMO_PUBLIC_KEY:
    raise SystemExit("Device must not use the public RFC 8032 demo key.")

message = ("SIGNER-LAB-V2 " + " ".join(fields)).encode("ascii")
Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key)).verify(
    bytes.fromhex(signature), message
)
print("SIGNATURE OK")
