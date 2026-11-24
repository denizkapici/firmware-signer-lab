"""Firmware signing code (signer_crypto.c) built for the host and checked
against an independent Python implementation of the V3 message."""

import ctypes
import subprocess
import tempfile
import unittest
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

import helpers

ROOT = Path(__file__).resolve().parents[1]
# The C code takes the seed as an argument; any test seed works.
SEED = bytes(range(32))
PUBLIC_KEY = helpers.raw_public_key(Ed25519PrivateKey.from_private_bytes(SEED))
FIELDS = ["a" * 32, "b" * 64, "staging", "1800000000"]


def message(fields, counter):
    return f"SIGNER-LAB-V3 {' '.join(fields)} {counter}".encode("ascii")


class CryptoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(directory.cleanup)
        library = Path(directory.name) / "signer-crypto.so"

        subprocess.run([
            "gcc", "-shared", "-fPIC", "-std=c11", "-O2",
            "-Wall", "-Wextra", "-Werror",
            "-Ifirmware", "-Ifirmware/vendor/monocypher",
            "firmware/signer_crypto.c",
            "firmware/vendor/monocypher/monocypher.c",
            "firmware/vendor/monocypher/monocypher-ed25519.c",
            "-o", str(library),
        ], cwd=ROOT, check=True)

        cls.library = ctypes.CDLL(str(library))
        cls.sign = cls.library.signer_sign_approval
        cls.sign.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_char_p, ctypes.c_char_p,
            ctypes.c_char_p, ctypes.c_char_p,
            ctypes.c_uint32,
        ]
        cls.sign.restype = ctypes.c_int

    def sign_fields(self, fields, counter=1, seed=SEED):
        output = (ctypes.c_uint8 * 64)()
        seed_buffer = None if seed is None else (ctypes.c_uint8 * 32)(*seed)
        result = self.sign(
            output, seed_buffer, *(field.encode("ascii") for field in fields), counter
        )
        return result, bytes(output)

    def verify(self, signature, fields, counter):
        Ed25519PublicKey.from_public_bytes(PUBLIC_KEY).verify(
            signature, message(fields, counter)
        )

    def test_c_signature_matches_python_message(self):
        for counter in (1, 9, 10, 12345, 0xFFFFFFFE):
            with self.subTest(counter=counter):
                result, signature = self.sign_fields(FIELDS, counter)
                self.assertEqual(result, 1)
                self.verify(signature, FIELDS, counter)

    def test_changed_fields_or_counter_invalidate_signature(self):
        _, signature = self.sign_fields(FIELDS, 7)
        for index, value in ((0, "c" * 32), (1, "d" * 64), (2, "production"),
                             (3, "1800000001")):
            changed = list(FIELDS)
            changed[index] = value
            with self.subTest(field=index):
                with self.assertRaises(InvalidSignature):
                    self.verify(signature, changed, 7)
        with self.assertRaises(InvalidSignature):
            self.verify(signature, FIELDS, 8)

    def test_other_seed_gives_other_signature(self):
        _, first = self.sign_fields(FIELDS)
        result, other = self.sign_fields(FIELDS, seed=bytes(range(1, 33)))
        self.assertEqual(result, 1)
        self.assertNotEqual(first, other)

    def test_null_seed_is_rejected(self):
        result, _ = self.sign_fields(FIELDS, seed=None)
        self.assertEqual(result, 0)

    def test_invalid_counters_are_rejected(self):
        for counter in (0, 0xFFFFFFFF):
            with self.subTest(counter=counter):
                result, _ = self.sign_fields(FIELDS, counter)
                self.assertEqual(result, 0)

    def test_maximum_fields_are_supported(self):
        fields = ["a" * 32, "b" * 64, "x" * 32, "9007199254740991"]
        result, signature = self.sign_fields(fields, 0xFFFFFFFE)
        self.assertEqual(result, 1)
        self.verify(signature, fields, 0xFFFFFFFE)

    def test_invalid_fields_are_rejected(self):
        for index, value in (
            (0, "a" * 8), (0, "A" * 32),
            (1, "g" * 64),
            (2, ""), (2, "_staging"), (2, "x" * 33),
            (2, "staging\n"),
            (3, "0"), (3, "01"), (3, "-1"), (3, "1.5"),
            (3, "9007199254740992"),
            (3, "99999999999999999"),
        ):
            fields = list(FIELDS)
            fields[index] = value
            with self.subTest(field=index, value=value):
                result, _ = self.sign_fields(fields)
                self.assertEqual(result, 0)


if __name__ == "__main__":
    unittest.main()
