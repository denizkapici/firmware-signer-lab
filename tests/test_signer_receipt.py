import json
import tempfile
import unittest
from pathlib import Path

from test_signer_client import client, signed_response


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        self.file = root / "firmware.bin"
        self.receipt = root / "approval.json"
        self.file.write_bytes(b"example firmware")
        self.request_id = "A0000001"
        self.digest = client.sha256_file(self.file)
        self.response = signed_response(self.request_id, self.digest)

    def save(self):
        client.save_receipt(
            self.receipt, self.request_id, self.digest, self.response, trusted_key=client.DEMO_PUBLIC_KEY
        )

    def test_receipt_round_trip(self):
        self.save()
        result = client.verify_receipt(self.file, self.receipt, trusted_key=client.DEMO_PUBLIC_KEY)
        self.assertEqual(result["request_id"], self.request_id)
        self.assertEqual(result["digest"], self.digest)

    def test_changed_file_is_rejected(self):
        self.save()
        self.file.write_bytes(b"modified firmware")
        with self.assertRaisesRegex(ValueError, "ozeti"):
            client.verify_receipt(self.file, self.receipt, trusted_key=client.DEMO_PUBLIC_KEY)

    def test_changed_receipt_fields_are_rejected(self):
        self.save()
        original = json.loads(self.receipt.read_text())
        changes = {
            "request_id": "B0000002",
            "signature": "0" * 128,
            "protocol": "SIGNER-LAB-V2",
            "key_id": "ATTACKER-KEY",
        }

        for field, value in changes.items():
            with self.subTest(field=field):
                changed = dict(original)
                changed[field] = value
                self.receipt.write_text(json.dumps(changed))
                with self.assertRaises(ValueError):
                    client.verify_receipt(self.file, self.receipt, trusted_key=client.DEMO_PUBLIC_KEY)

    def test_unsigned_approval_cannot_be_saved(self):
        with self.assertRaises(ValueError):
            client.save_receipt(
                self.receipt, self.request_id, self.digest,
                f"APPROVED {self.request_id} {self.digest}", trusted_key=client.DEMO_PUBLIC_KEY,
            )
        self.assertFalse(self.receipt.exists())

    def test_existing_receipt_is_not_overwritten(self):
        self.save()
        original = self.receipt.read_bytes()
        with self.assertRaises(FileExistsError):
            self.save()
        self.assertEqual(self.receipt.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
