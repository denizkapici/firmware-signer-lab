#!/usr/bin/env python3
"""Prepare approval requests and validate firmware responses."""

import argparse
import hashlib
import re
import secrets
from pathlib import Path
from signer_key_policy import DEMO_PUBLIC_KEY, load_trusted_key, key_id

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


def validate_response(line, request_id, digest, *, trusted_key):
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
            trusted_key
        )
        try:
            public_key.verify(
                bytes.fromhex(signature_hex),
                approval_message(request_id, digest),
            )
        except InvalidSignature as error:
            raise ValueError("Ed25519 imzasi gecersiz.") from error

    return result


def exchange_uart(port, request_id, digest, timeout, *, trusted_key):
    return exchange_command(
        port, build_request(request_id, digest), timeout,
        lambda line: validate_response(
            line, request_id, digest, trusted_key=trusted_key
        ),
        max_line=256,
    )


def exchange_command(port, command, timeout, validate_line, *, max_line=512):
    # Linux PTY transport. No additional Python package is required.
    import os
    import select
    import termios
    import time
    import tty

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
                if len(buffer) > max_line:
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

                result = validate_line(line)

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
                try:
                    termios.tcsetattr(fd, termios.TCSANOW, old_settings)
                except termios.error as error:
                    # A disconnected PTY cannot restore terminal settings.
                    if error.args[0] not in (5, 6):
                        raise ValueError(
                            "UART terminal ayarlari geri yuklenemedi."
                        ) from error
        finally:
            os.close(fd)



RECEIPT_PROTOCOL = "SIGNER-LAB-V1"
RECEIPT_KEY_ID = "RFC8032-TEST1-DEMO"


def save_receipt(path, request_id, digest, response, *, trusted_key):
    import json

    result = validate_response(response, request_id, digest, trusted_key=trusted_key)
    if result != "APPROVED":
        raise ValueError("Yalnizca imzasi dogrulanmis onay kaydedilebilir.")

    signature = response.rstrip("\r\n").split(" ")[3]
    receipt = {
        "protocol": RECEIPT_PROTOCOL,
        "key_id": key_id(trusted_key),
        "request_id": request_id,
        "digest": digest,
        "signature": signature,
    }

    # Exclusive creation: never overwrite an existing receipt.
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(receipt, stream, indent=2)
        stream.write("\n")


def verify_receipt(file_path, receipt_path, *, trusted_key):
    import json

    def unique_fields(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Belgede tekrarlanan alan var.")
            result[key] = value
        return result

    with Path(receipt_path).open("r", encoding="utf-8") as stream:
        receipt = json.load(stream, object_pairs_hook=unique_fields)

    expected = {"protocol", "key_id", "request_id", "digest", "signature"}
    if not isinstance(receipt, dict) or set(receipt) != expected:
        raise ValueError("Belge alanlari gecersiz.")

    if not all(isinstance(value, str) for value in receipt.values()):
        raise ValueError("Belge alanlari metin olmali.")

    if receipt["protocol"] != RECEIPT_PROTOCOL:
        raise ValueError("Desteklenmeyen protokol.")
    if receipt["key_id"] != key_id(trusted_key):
        raise ValueError("Guvenilmeyen anahtar kimligi.")

    build_request(receipt["request_id"], receipt["digest"])
    actual_digest = sha256_file(file_path)

    if actual_digest != receipt["digest"]:
        raise ValueError("Dosyanin ozeti onay belgesiyle eslesmiyor.")

    response = (
        f'APPROVED {receipt["request_id"]} '
        f'{receipt["digest"]} {receipt["signature"]}'
    )
    validate_response(response, receipt["request_id"], actual_digest, trusted_key=trusted_key)
    return receipt


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
    parser.add_argument(
        "--receipt-out", type=Path,
        help="Dogrulanmis onayin kaydedilecegi yeni JSON dosyasi",
    )
    parser.add_argument(
        "--verify-receipt", type=Path,
        help="Dosyaya ait onay belgesini cevrimdisi dogrula",
    )
    trust = parser.add_mutually_exclusive_group()
    trust.add_argument(
        "--allow-demo-key", action="store_true",
        help="Herkese acik demo anahtarini acikca kullan",
    )
    trust.add_argument(
        "--public-key-file", type=Path,
        help="Guvenilen acik anahtar: 64 hexadecimal karakter",
    )
    args = parser.parse_args()

    trusted_key = None
    needs_trust = (
        args.verify_receipt is not None
        or args.port is not None
        or args.response is not None
    )
    if needs_trust or args.allow_demo_key or args.public_key_file is not None:
        try:
            trusted_key = load_trusted_key(
                args.public_key_file, args.allow_demo_key
            )
        except (OSError, ValueError) as error:
            parser.exit(1, f"Hata: {error}\n")

    key_label = (
        "DEMO ANAHTARI"
        if trusted_key == DEMO_PUBLIC_KEY
        else "SECILEN ACIK ANAHTAR"
    )

    if args.verify_receipt is not None:
        if (args.port is not None or args.response is not None
                or args.receipt_out is not None
                or args.request_id is not None):
            parser.error("--verify-receipt diger islem secenekleriyle kullanilamaz.")
        try:
            verify_receipt(args.file, args.verify_receipt, trusted_key=trusted_key)
        except (OSError, ValueError) as error:
            parser.exit(1, f"Hata: {error}\n")
        print(f"Dosya ozeti ve Ed25519 imzasi dogrulandi: {key_label}.")
        return 0

    if (args.receipt_out is not None
            and args.port is None and args.response is None):
        parser.error("--receipt-out icin --port veya --response gerekli.")

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
                args.port, request_id, digest, args.timeout,
                trusted_key=trusted_key,
            )

        if args.response is None:
            print(request)
            return 0

        result = validate_response(args.response, request_id, digest, trusted_key=trusted_key)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Hata: {error}\n")

    if result == "APPROVED":
        if args.receipt_out is not None:
            try:
                save_receipt(
                    args.receipt_out, request_id, digest, args.response,
                    trusted_key=trusted_key,
                )
            except (OSError, ValueError) as error:
                parser.exit(1, f"Belge kaydedilemedi: {error}\n")
            print(f"Onay belgesi kaydedildi: {args.receipt_out}")
        if trusted_key == DEMO_PUBLIC_KEY:
            print("Eslesen APPROVED yaniti alindi; Ed25519 imzasi DEMO anahtariyla dogrulandi.")
        else:
            print("Eslesen APPROVED yaniti alindi; Ed25519 imzasi secilen acik anahtarla dogrulandi.")
        return 0

    print(f"Istek henuz onaylanmadi. Durum: {result}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
