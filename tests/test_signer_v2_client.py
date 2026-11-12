import importlib.util
import sys
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location(
    "signer_v2_client", SCRIPTS / "signer-v2.py"
)
client = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(client)


class V2ClientTests(unittest.TestCase):
    def setUp(self):
        self.expected = ("a" * 32, "b" * 64, "staging", 1800000000)
        self.private = Ed25519PrivateKey.generate()
        self.public = self.private.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )

    def response(self, fields=None):
        fields = self.expected if fields is None else fields
        message = (
            "SIGNER-LAB-V2 " + " ".join(map(str, fields))
        ).encode("ascii")
        signature = self.private.sign(message).hex()
        return "APPROVED2 " + " ".join(map(str, fields)) + " " + signature

    def test_valid_signed_response(self):
        parsed = client.checked_response(
            self.response() + "\r\n", self.expected, self.public
        )
        self.assertEqual(parsed[0], "APPROVED2")
        self.assertEqual(len(parsed[5]), 64)

    def test_valid_signature_for_wrong_operation_is_rejected(self):
        for index, value in enumerate(
            ("c" * 32, "d" * 64, "production", 1800000001)
        ):
            fields = list(self.expected)
            fields[index] = value
            with self.subTest(field=index):
                with self.assertRaisesRegex(ValueError, "does not match"):
                    client.checked_response(
                        self.response(tuple(fields)), self.expected, self.public
                    )

    def test_corrupted_signature_is_rejected(self):
        parts = self.response().split(" ")
        signature = bytearray.fromhex(parts[-1])
        signature[0] ^= 1
        parts[-1] = signature.hex()
        with self.assertRaisesRegex(ValueError, "Invalid V2 signature"):
            client.checked_response(
                " ".join(parts), self.expected, self.public
            )

    def test_unsigned_approval_is_rejected(self):
        response = "APPROVED2 " + " ".join(map(str, self.expected))
        with self.assertRaises(ValueError):
            client.checked_response(response, self.expected, self.public)

    def test_nonapproval_states_are_not_approvals(self):
        for status in ("PENDING2", "CANCELLED2", "TIMEOUT2"):
            with self.subTest(status=status):
                line = status + " " + " ".join(map(str, self.expected))
                parsed = client.checked_response(
                    line, self.expected, self.public
                )
                self.assertEqual(parsed[0], status)
                self.assertIsNone(parsed[5])

    def test_malformed_responses_are_rejected(self):
        valid = self.response()
        for line in (
            valid.replace("APPROVED2 ", "APPROVED ", 1),
            valid.replace("APPROVED2 ", "APPROVED2  ", 1),
            valid.replace("1800000000", "01800000000", 1),
            valid + " extra",
            valid + "\nextra",
        ):
            with self.subTest(line=line):
                with self.assertRaises(ValueError):
                    client.parse_response(line)


if __name__ == "__main__":
    unittest.main()
