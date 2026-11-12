"""Explicit host trust selection. Contains no private keys."""

import hashlib
import re
from pathlib import Path

DEMO_PUBLIC_KEY = bytes.fromhex(
    "d75a980182b10ab7d54bfed3c964073a"
    "0ee172f3daa62325af021a68f707511a"
)
DEMO_KEY_ID = "RFC8032-TEST1-DEMO"


def load_trusted_key(public_key_file=None, allow_demo_key=False):
    if public_key_file is not None and allow_demo_key:
        raise ValueError("Acik anahtar dosyasi ve demo secimi birlikte kullanilamaz.")

    if allow_demo_key:
        return DEMO_PUBLIC_KEY

    if public_key_file is None:
        raise ValueError("Guvenilecek acik anahtar veya acik demo secimi gerekli.")

    text = Path(public_key_file).read_text(encoding="ascii").strip()
    if re.fullmatch(r"[0-9a-fA-F]{64}", text) is None:
        raise ValueError("Acik anahtar dosyasi 64 hexadecimal karakter icermeli.")

    public_key = bytes.fromhex(text)
    if public_key == DEMO_PUBLIC_KEY:
        raise ValueError("Demo anahtari icin --allow-demo-key kullanilmali.")

    return public_key


def key_id(public_key):
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise ValueError("Ed25519 acik anahtari 32 bayt olmali.")

    if public_key == DEMO_PUBLIC_KEY:
        return DEMO_KEY_ID

    return "ED25519-SHA256-" + hashlib.sha256(public_key).hexdigest()
