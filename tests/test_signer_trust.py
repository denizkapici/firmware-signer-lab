import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from test_signer_client import client, SCRIPT


class TrustIntegrationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)

        self.file = root / "firmware.bin"
        self.receipt = root / "approval.json"
        self.key_file = root / "public-key.hex"
        self.file.write_bytes(b"trust policy test")

        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.raw_public_key(self.private_key)
        self.key_file.write_text(self.public_key.hex() + "\n")

        self.request_id = "A0000001"
        self.digest = client.sha256_file(self.file)
        message = (
            f"SIGNER-LAB-V1 {self.request_id} {self.digest}"
        ).encode("ascii")
        signature = self.private_key.sign(message).hex()
        self.response = (
            f"APPROVED {self.request_id} {self.digest} {signature}"
        )

    @staticmethod
    def raw_public_key(private_key):
        return private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )

    def save_receipt(self):
        client.save_receipt(
            self.receipt, self.request_id, self.digest, self.response,
            trusted_key=self.public_key,
        )

    def run_cli(self, *arguments):
        return subprocess.run(
            [sys.executable, str(SCRIPT), str(self.file), *arguments],
            capture_output=True,
            text=True,
            timeout=10,
        )

    def test_selected_key_verifies_signature(self):
        result = client.validate_response(
            self.response, self.request_id, self.digest,
            trusted_key=self.public_key,
        )
        self.assertEqual(result, "APPROVED")

    def test_wrong_key_rejects_signature(self):
        wrong_key = self.raw_public_key(Ed25519PrivateKey.generate())
        with self.assertRaisesRegex(ValueError, "imzasi gecersiz"):
            client.validate_response(
                self.response, self.request_id, self.digest,
                trusted_key=wrong_key,
            )

    def test_cli_verifies_receipt_with_selected_key_file(self):
        self.save_receipt()
        result = self.run_cli(
            "--verify-receipt", str(self.receipt),
            "--public-key-file", str(self.key_file),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("SECILEN ACIK ANAHTAR", result.stdout)
        self.assertNotIn("DEMO ANAHTARI", result.stdout)

    def test_cli_rejects_receipt_with_wrong_key_file(self):
        self.save_receipt()
        wrong_key = self.raw_public_key(Ed25519PrivateKey.generate())
        self.key_file.write_text(wrong_key.hex())
        result = self.run_cli(
            "--verify-receipt", str(self.receipt),
            "--public-key-file", str(self.key_file),
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("Guvenilmeyen anahtar kimligi", result.stderr)

    def test_cli_requires_explicit_trust(self):
        self.save_receipt()
        result = self.run_cli("--verify-receipt", str(self.receipt))
        self.assertEqual(result.returncode, 1)
        self.assertIn("acik demo secimi gerekli", result.stderr)

    def test_cli_rejects_conflicting_trust_options(self):
        result = self.run_cli(
            "--verify-receipt", str(self.receipt),
            "--public-key-file", str(self.key_file),
            "--allow-demo-key",
        )
        self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
