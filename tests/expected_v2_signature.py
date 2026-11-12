"""Independent expected signature for the public demo key."""

import sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

if len(sys.argv) != 5:
    raise SystemExit("Expected: request_id digest target expires_at")

key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc4"
    "4449c5697b326919703bac031cae7f60"
))
message = ("SIGNER-LAB-V2 " + " ".join(sys.argv[1:])).encode("ascii")
print(key.sign(message).hex())
