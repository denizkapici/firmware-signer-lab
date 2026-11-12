#!/usr/bin/env python3
"""Prepare approval requests and validate firmware responses."""

import argparse
import hashlib
import re
import secrets
from pathlib import Path

ID_PATTERN = re.compile(r"[0-9a-fA-F]{8}")
DIGEST_PATTERN = re.compile(r"[0-9a-fA-F]{64}")
RESULTS = {"PENDING", "APPROVED", "CANCELLED", "TIMEOUT"}


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_request(request_id, digest):
    if ID_PATTERN.fullmatch(request_id) is None:
        raise ValueError("Istek kimligi tam 8 hexadecimal karakter olmali.")
    if DIGEST_PATTERN.fullmatch(digest) is None:
        raise ValueError("Ozet tam 64 hexadecimal karakter olmali.")
    return f"REQUEST {request_id} {digest}"


# RFC 8032 TEST 1 public key. Demonstration only.
DEMO_PUBLIC_KEY_HEX = (
    "d75a980182b10ab7d54bfed3c964073a"
    "0ee172f3daa62325af021a68f707511a"
)


def approval_message(request_id, digest):
    build_request(request_id, digest)
    return f"SIGNER-LAB-V1 {request_id} {digest}".encode("ascii")


def validate_response(line, request_id, digest):
    build_request(request_id, digest)

    if line.endswith("\r\n"):
        line = line[:-2]
    elif line.endswith("\r") or line.endswith("\n"):
        line = line[:-1]

    parts = line.split(" ")
    if not parts or parts[0] not in RESULTS:
        raise ValueError("Beklenmeyen yanit turu.")

    result = parts[0]
    expected_fields = 4 if result == "APPROVED" else 3
    if len(parts) != expected_fields:
        raise ValueError("Yanit bicimi veya imza alani gecersiz.")

    received_id, received_digest = parts[1:3]
    if received_id != request_id:
        raise ValueError("Yanit baska bir istege ait.")
    if received_digest != digest:
        raise ValueError("Yanittaki ozet beklenen dosya ozetiyle eslesmiyor.")

    if result == "APPROVED":
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )

        signature_hex = parts[3]
        if re.fullmatch(r"[0-9a-fA-F]{128}", signature_hex) is None:
            raise ValueError("Imza tam 128 hexadecimal karakter olmali.")

        public_key = Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(DEMO_PUBLIC_KEY_HEX)
        )
        try:
            public_key.verify(
                bytes.fromhex(signature_hex),
                approval_message(request_id, digest),
            )
        except InvalidSignature as error:
            raise ValueError("Ed25519 imzasi gecersiz.") from error

    return result


def exchange_uart(port, request_id, digest, timeout):
    # Linux PTY transport. No additional Python package is required.
    import os
    import select
    import termios
    import time
    import tty

    command = build_request(request_id, digest)
    fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    old_settings = None

    try:
        old_settings = termios.tcgetattr(fd)
        tty.setraw(fd)
        termios.tcflush(fd, termios.TCIFLUSH)

        deadline = time.monotonic() + timeout
        outgoing = (command + "\r\n").encode("ascii")
        offset = 0

        while offset < len(outgoing):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError("UART yazma suresi doldu.")

            _, writable, _ = select.select([], [fd], [], remaining)
            if not writable:
                raise ValueError("UART yazma suresi doldu.")

            try:
                count = os.write(fd, outgoing[offset:])
            except BlockingIOError:
                continue

            if count == 0:
                raise ValueError("UART baglantisi kapandi.")
            offset += count

        print(f"Gonderildi: {command}", flush=True)

        buffer = bytearray()
        pending_seen = False

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError(
                    "Host bekleme suresi doldu; firmware sonucu bilinmiyor."
                )

            readable, _, _ = select.select([fd], [], [], remaining)
            if not readable:
                raise ValueError(
                    "Host bekleme suresi doldu; firmware sonucu bilinmiyor."
                )

            try:
                chunk = os.read(fd, 4096)
            except BlockingIOError:
                continue

            if not chunk:
                raise ValueError("UART baglantisi kapandi.")

            for byte in chunk:
                buffer.append(byte)
                if len(buffer) > 256:
                    raise ValueError("UART yaniti izin verilenden uzun.")

                if byte != 10:
                    continue

                line = buffer.decode("ascii")
                buffer.clear()

                # Startup can arrive if firmware has just been started.
                if line == "Signer firmware started\r\n":
                    continue

                if line.startswith("ERR "):
                    raise ValueError("Firmware: " + line.rstrip("\r\n"))

                result = validate_response(line, request_id, digest)

                if result == "PENDING":
                    if pending_seen:
                        raise ValueError("Tekrarlanan PENDING yaniti.")
                    pending_seen = True
                    print("PENDING: buton onayi bekleniyor.", flush=True)
                    continue

                if not pending_seen:
                    raise ValueError("PENDING alinmadan sonuc geldi.")

                print("Alindi: " + line.rstrip("\r\n"), flush=True)
                return line
    finally:
        try:
            if old_settings is not None:
                termios.tcsetattr(fd, termios.TCSANOW, old_settings)
        finally:
            os.close(fd)


def main():
    parser = argparse.ArgumentParser(
        description="Dosya icin onay istegi olusturur."
    )
    parser.add_argument("file", type=Path, help="Onaylanacak dosya")
    parser.add_argument("--request-id", help="8 hexadecimal karakter")
    parser.add_argument(
        "--response",
        help="Kontrol edilecek tek firmware yanit satiri",
    )
    parser.add_argument(
        "--port", help="Linux sanal UART yolu, ornek: /tmp/signer-uart"
    )
    parser.add_argument(
        "--timeout", type=float, default=15.0,
        help="Host bekleme suresi, saniye (varsayilan: 15)",
    )
    args = parser.parse_args()

    import math
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("--timeout sonlu ve pozitif olmali.")
    if args.port is not None and args.response is not None:
        parser.error("--port ve --response birlikte kullanilamaz.")

    if args.response is not None and args.request_id is None:
        parser.error("--response kullanirken --request-id de belirtilmeli.")

    request_id = args.request_id or secrets.token_hex(4)

    try:
        digest = sha256_file(args.file)
        request = build_request(request_id, digest)

        if args.port is not None:
            args.response = exchange_uart(
                args.port, request_id, digest, args.timeout
            )

        if args.response is None:
            print(request)
            return 0

        result = validate_response(args.response, request_id, digest)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Hata: {error}\n")

    if result == "APPROVED":
        print("Eslesen APPROVED yaniti alindi; Ed25519 imzasi DEMO anahtariyla dogrulandi.")
        return 0

    print(f"Istek henuz onaylanmadi. Durum: {result}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
