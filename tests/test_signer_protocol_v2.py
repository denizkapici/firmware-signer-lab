import importlib.util
import unittest
from pathlib import Path

MODULE = (
    Path(__file__).resolve().parents[1]
    / "scripts" / "signer_protocol_v2.py"
)
SPEC = importlib.util.spec_from_file_location("signer_protocol_v2", MODULE)
protocol = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(protocol)


class ProtocolV2Tests(unittest.TestCase):
    def setUp(self):
        self.fields = {
            "request_id": "a" * 32,
            "digest": "b" * 64,
            "target": "staging",
            "expires_at": 1800000000,
        }

    def test_exact_request_format(self):
        expected = (
            f"REQUEST2 {'a' * 32} {'b' * 64} staging 1800000000"
        )
        self.assertEqual(protocol.build_request(**self.fields), expected)

    def test_exact_signed_message(self):
        expected = (
            f"SIGNER-LAB-V2 {'a' * 32} {'b' * 64} staging 1800000000"
        ).encode("ascii")
        self.assertEqual(protocol.approval_message(**self.fields), expected)

    def test_every_bound_field_changes_the_message(self):
        original = protocol.approval_message(**self.fields)
        for name, value in (
            ("request_id", "c" * 32),
            ("digest", "d" * 64),
            ("target", "production"),
            ("expires_at", 1800000001),
        ):
            with self.subTest(field=name):
                changed = dict(self.fields)
                changed[name] = value
                self.assertNotEqual(
                    protocol.approval_message(**changed), original
                )

    def test_invalid_fields_are_rejected(self):
        for name, value in (
            ("request_id", "a" * 8),
            ("request_id", "A" * 32),
            ("digest", "g" * 64),
            ("target", "staging production"),
            ("target", "staging\n"),
            ("target", "x" * 33),
            ("expires_at", True),
            ("expires_at", 0),
            ("expires_at", 1.5),
            ("expires_at", "1800000000"),
            ("expires_at", 9007199254740992),
        ):
            with self.subTest(field=name, value=value):
                changed = dict(self.fields)
                changed[name] = value
                with self.assertRaises(ValueError):
                    protocol.approval_message(**changed)

    def test_longest_request_fits_256_byte_buffer(self):
        self.fields["target"] = "x" * 32
        self.fields["expires_at"] = 9007199254740991
        command = protocol.build_request(**self.fields)
        self.assertLessEqual(len(command.encode("ascii")) + 1, 256)


if __name__ == "__main__":
    unittest.main()
