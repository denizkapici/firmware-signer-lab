import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import helpers
from helpers import raw_public_key, signed_line
from signer_lab.protocol import Operation, parse_response, sha256_file
from signer_lab.receipt import load_receipt, save_receipt, verify_receipt


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        self.file = root / "firmware.bin"
        self.file.write_bytes(b"receipt test firmware")
        self.receipt = root / "approval.json"

        self.private = Ed25519PrivateKey.generate()
        self.public = raw_public_key(self.private)
        self.fields = ("a" * 32, sha256_file(self.file), "staging", 1800000000)
        self.response = parse_response(signed_line(self.private, self.fields))

    def rewrite(self, **changes):
        data = json.loads(self.receipt.read_text())
        data.update(changes)
        self.receipt.write_text(json.dumps(data))

    def test_receipt_round_trip(self):
        save_receipt(self.receipt, self.response, trusted_key=self.public)
        loaded = verify_receipt(self.file, self.receipt, trusted_key=self.public)
        self.assertEqual(loaded, self.response)
        self.assertEqual(loaded.operation, Operation(*self.fields))

    def test_receipt_contains_expected_fields(self):
        save_receipt(self.receipt, self.response, trusted_key=self.public)
        data = json.loads(self.receipt.read_text())
        self.assertEqual(data["protocol"], "SIGNER-LAB-V2")
        self.assertEqual(data["target"], "staging")
        self.assertEqual(data["expires_at"], 1800000000)
        self.assertTrue(data["key_id"].startswith("ED25519-SHA256-"))

    def test_changed_file_is_rejected(self):
        save_receipt(self.receipt, self.response, trusted_key=self.public)
        self.file.write_bytes(b"tampered firmware")
        with self.assertRaisesRegex(ValueError, "digest"):
            verify_receipt(self.file, self.receipt, trusted_key=self.public)

    def test_wrong_target_is_rejected(self):
        save_receipt(self.receipt, self.response, trusted_key=self.public)
        with self.assertRaisesRegex(ValueError, "another target"):
            verify_receipt(self.file, self.receipt, trusted_key=self.public, target="production")

    def test_changed_receipt_fields_are_rejected(self):
        for changes in (
            {"request_id": "c" * 32},
            {"target": "production"},
            {"expires_at": 1800000001},
            {"expires_at": "1800000000"},
            {"expires_at": True},
            {"protocol": "SIGNER-LAB-V1"},
            {"key_id": "RFC8032-TEST1-DEMO"},
            {"signature": "00" * 64},
            {"signature": "zz"},
            {"extra": 1},
        ):
            with self.subTest(changes=changes):
                if self.receipt.exists():
                    self.receipt.unlink()
                save_receipt(self.receipt, self.response, trusted_key=self.public)
                self.rewrite(**changes)
                with self.assertRaises(ValueError):
                    load_receipt(self.receipt, trusted_key=self.public)

    def test_duplicate_json_field_is_rejected(self):
        save_receipt(self.receipt, self.response, trusted_key=self.public)
        text = self.receipt.read_text().replace(
            '"target": "staging"', '"target": "staging", "target": "production"'
        )
        self.receipt.write_text(text)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            load_receipt(self.receipt, trusted_key=self.public)

    def test_other_trusted_key_is_rejected(self):
        save_receipt(self.receipt, self.response, trusted_key=self.public)
        other = raw_public_key(Ed25519PrivateKey.generate())
        with self.assertRaises(ValueError):
            load_receipt(self.receipt, trusted_key=other)

    def test_unsigned_response_cannot_be_saved(self):
        pending = parse_response("PENDING2 " + helpers.fields_text(self.fields))
        with self.assertRaises(ValueError):
            save_receipt(self.receipt, pending, trusted_key=self.public)
        self.assertFalse(self.receipt.exists())

    def test_existing_receipt_is_not_overwritten(self):
        self.receipt.write_text("keep")
        with self.assertRaises(FileExistsError):
            save_receipt(self.receipt, self.response, trusted_key=self.public)
        self.assertEqual(self.receipt.read_text(), "keep")


if __name__ == "__main__":
    unittest.main()
