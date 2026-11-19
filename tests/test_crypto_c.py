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


class CryptoV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(directory.cleanup)
        library = Path(directory.name) / "signer-v2.so"

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
        cls.sign = cls.library.signer_sign_approval_v2
        cls.sign.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_char_p, ctypes.c_char_p,
            ctypes.c_char_p, ctypes.c_char_p,
        ]
        cls.sign.restype = ctypes.c_int

    def sign_fields(self, fields):
        output = (ctypes.c_uint8 * 64)()
        seed = (ctypes.c_uint8 * 32)(*SEED)
        result = self.sign(
            output, seed, *(field.encode("ascii") for field in fields)
        )
        return result, bytes(output)

    def test_c_signature_matches_python_message(self):
        fields = ["a" * 32, "b" * 64, "staging", "1800000000"]
        result, signature = self.sign_fields(fields)
        self.assertEqual(result, 1)
        message = ("SIGNER-LAB-V2 " + " ".join(fields)).encode("ascii")
        Ed25519PublicKey.from_public_bytes(PUBLIC_KEY).verify(
            signature, message
        )

    def test_changed_fields_invalidate_signature(self):
        fields = ["a" * 32, "b" * 64, "staging", "1800000000"]
        result, signature = self.sign_fields(fields)
        self.assertEqual(result, 1)
        verifier = Ed25519PublicKey.from_public_bytes(PUBLIC_KEY)

        for index, value in enumerate(
            ["c" * 32, "d" * 64, "production", "1800000001"]
        ):
            changed = list(fields)
            changed[index] = value
            message = ("SIGNER-LAB-V2 " + " ".join(changed)).encode("ascii")
            with self.subTest(field=index):
                with self.assertRaises(InvalidSignature):
                    verifier.verify(signature, message)

    def test_other_seed_gives_other_signature(self):
        fields = ["a" * 32, "b" * 64, "staging", "1800000000"]
        _, first = self.sign_fields(fields)
        output = (ctypes.c_uint8 * 64)()
        other = (ctypes.c_uint8 * 32)(*bytes(range(1, 33)))
        self.assertEqual(
            self.sign(output, other, *(f.encode("ascii") for f in fields)), 1
        )
        self.assertNotEqual(bytes(output), first)

    def test_null_seed_is_rejected(self):
        output = (ctypes.c_uint8 * 64)()
        fields = ["a" * 32, "b" * 64, "staging", "1800000000"]
        self.assertEqual(self.sign(output, None, *(f.encode("ascii") for f in fields)), 0)

    def test_maximum_fields_are_supported(self):
        fields = ["a" * 32, "b" * 64, "x" * 32, "9007199254740991"]
        result, signature = self.sign_fields(fields)
        self.assertEqual(result, 1)
        message = ("SIGNER-LAB-V2 " + " ".join(fields)).encode("ascii")
        Ed25519PublicKey.from_public_bytes(PUBLIC_KEY).verify(
            signature, message
        )

    def test_invalid_fields_are_rejected(self):
        original = ["a" * 32, "b" * 64, "staging", "1800000000"]
        for index, value in (
            (0, "a" * 8), (0, "A" * 32),
            (1, "g" * 64),
            (2, ""), (2, "_staging"), (2, "x" * 33),
            (2, "staging\n"),
            (3, "0"), (3, "01"), (3, "-1"), (3, "1.5"),
            (3, "9007199254740992"),
            (3, "99999999999999999"),
        ):
            fields = list(original)
            fields[index] = value
            with self.subTest(field=index, value=value):
                result, _ = self.sign_fields(fields)
                self.assertEqual(result, 0)


if __name__ == "__main__":
    unittest.main()
