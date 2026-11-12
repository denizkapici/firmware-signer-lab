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


def validate_response(line, request_id, digest):
    # Validate the expected values as well.
    build_request(request_id, digest)

    # Accept a single line with an optional CR, LF or CRLF ending.
    if line.endswith("\r\n"):
        line = line[:-2]
    elif line.endswith("\r") or line.endswith("\n"):
        line = line[:-1]

    parts = line.split(" ")
    if len(parts) != 3:
        raise ValueError("Yanit bicimi gecersiz.")

    result, received_id, received_digest = parts
    if result not in RESULTS:
        raise ValueError("Beklenmeyen yanit turu.")
    if received_id != request_id:
        raise ValueError("Yanit baska bir istege ait.")
    if received_digest != digest:
        raise ValueError("Yanittaki ozet beklenen dosya ozetiyle eslesmiyor.")

    return result


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
    args = parser.parse_args()

    if args.response is not None and args.request_id is None:
        parser.error("--response kullanirken --request-id de belirtilmeli.")

    request_id = args.request_id or secrets.token_hex(4)

    try:
        digest = sha256_file(args.file)
        request = build_request(request_id, digest)

        if args.response is None:
            print(request)
            return 0

        result = validate_response(args.response, request_id, digest)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Hata: {error}\n")

    if result == "APPROVED":
        print("Eslesen APPROVED yaniti alindi; kriptografik imza dogrulanmadi.")
        return 0

    print(f"Istek henuz onaylanmadi. Durum: {result}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
