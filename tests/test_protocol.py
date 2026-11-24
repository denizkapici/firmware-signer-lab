import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import helpers
from helpers import raw_public_key, signed_line
from signer_lab import protocol
from signer_lab.protocol import Operation


class EncodingTests(unittest.TestCase):
    def setUp(self):
        self.fields = {
            "request_id": "a" * 32,
            "digest": "b" * 64,
            "target": "staging",
            "expires_at": 1800000000,
        }

    def test_exact_request_format(self):
        expected = f"REQUEST3 {'a' * 32} {'b' * 64} staging 1800000000"
        self.assertEqual(protocol.build_request(**self.fields), expected)

    def test_exact_signed_message(self):
        expected = (
            f"SIGNER-LAB-V3 {'a' * 32} {'b' * 64} staging 1800000000 42".encode("ascii")
        )
        self.assertEqual(protocol.approval_message(**self.fields, counter=42), expected)

    def test_every_bound_field_changes_the_message(self):
        original = protocol.approval_message(**self.fields, counter=1)
        for name, value in (
            ("request_id", "c" * 32),
            ("digest", "d" * 64),
            ("target", "production"),
            ("expires_at", 1800000001),
            ("counter", 2),
        ):
            with self.subTest(field=name):
                changed = dict(self.fields, counter=1)
                changed[name] = value
                self.assertNotEqual(protocol.approval_message(**changed), original)

    def test_invalid_counters_are_rejected(self):
        for counter in (0, -1, 2**32 - 1, 2**32, True, 1.0, "1"):
            with self.subTest(counter=counter):
                with self.assertRaises(ValueError):
                    protocol.approval_message(**self.fields, counter=counter)

    def test_invalid_fields_are_rejected(self):
        for name, value in (
            ("request_id", "a" * 8),
            ("request_id", "A" * 32),
            ("digest", "g" * 64),
            ("target", "staging production"),
            ("target", "staging\n"),
            ("target", "_staging"),
            ("target", "x" * 33),
            ("expires_at", True),
            ("expires_at", 0),
            ("expires_at", 1.5),
            ("expires_at", "1800000000"),
            ("expires_at", 2**53),
        ):
            with self.subTest(field=name, value=value):
                changed = dict(self.fields, **{name: value})
                with self.assertRaises(ValueError):
                    protocol.approval_message(**changed, counter=1)
                with self.assertRaises(ValueError):
                    Operation(**changed)

    def test_longest_request_fits_firmware_line_limit(self):
        operation = Operation("a" * 32, "b" * 64, "x" * 32, 2**53 - 1)
        # Firmware accepts at most 255 characters before the line ending.
        self.assertLessEqual(len(operation.request_line()), 255)


class ResponseTests(unittest.TestCase):
    def setUp(self):
        self.fields = ("a" * 32, "b" * 64, "staging", 1800000000)
        self.operation = Operation(*self.fields)
        self.private = Ed25519PrivateKey.generate()
        self.public = raw_public_key(self.private)

    def test_valid_signed_response(self):
        line = signed_line(self.private, self.fields) + "\r\n"
        response = protocol.check_response(line, self.operation, self.public)
        self.assertEqual(response.status, "APPROVED3")
        self.assertEqual(response.operation, self.operation)
        self.assertEqual(len(response.signature), 64)

    def test_demo_key_signature_matches_demo_public_key(self):
        line = signed_line(helpers.demo_private_key(), self.fields)
        from signer_lab.keys import DEMO_PUBLIC_KEY

        protocol.check_response(line, self.operation, DEMO_PUBLIC_KEY)

    def test_valid_signature_for_wrong_operation_is_rejected(self):
        for index, value in enumerate(("c" * 32, "d" * 64, "production", 1800000001)):
            fields = list(self.fields)
            fields[index] = value
            with self.subTest(field=index):
                with self.assertRaisesRegex(ValueError, "does not match"):
                    protocol.check_response(
                        signed_line(self.private, fields), self.operation, self.public
                    )

    def test_corrupted_signature_is_rejected(self):
        parts = signed_line(self.private, self.fields).split(" ")
        signature = bytearray.fromhex(parts[-1])
        signature[0] ^= 1
        parts[-1] = signature.hex()
        with self.assertRaisesRegex(ValueError, "Invalid V3 signature"):
            protocol.check_response(" ".join(parts), self.operation, self.public)

    def test_other_key_is_rejected(self):
        other = Ed25519PrivateKey.generate()
        with self.assertRaisesRegex(ValueError, "Invalid V3 signature"):
            protocol.check_response(signed_line(other, self.fields), self.operation, self.public)

    def test_unsigned_approval_is_rejected(self):
        line = "APPROVED3 " + helpers.fields_text(self.fields)
        with self.assertRaises(ValueError):
            protocol.check_response(line, self.operation, self.public)

    def test_nonapproval_states_are_not_approvals(self):
        for status in ("PENDING3", "CANCELLED3", "TIMEOUT3"):
            with self.subTest(status=status):
                line = f"{status} {helpers.fields_text(self.fields)}"
                response = protocol.check_response(line, self.operation, self.public)
                self.assertEqual(response.status, status)
                self.assertIsNone(response.signature)

    def test_malformed_responses_are_rejected(self):
        valid = signed_line(self.private, self.fields)
        for line in (
            valid.replace("APPROVED3 ", "APPROVED ", 1),
            valid.replace("APPROVED3 ", "APPROVED3  ", 1),
            valid.replace("1800000000", "01800000000", 1),
            valid.upper(),
            valid + " extra",
            valid + "\nextra",
            "",
        ):
            with self.subTest(line=line):
                with self.assertRaises(ValueError):
                    protocol.parse_response(line)


if __name__ == "__main__":
    unittest.main()
