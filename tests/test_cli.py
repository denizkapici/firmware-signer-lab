"""End-to-end CLI tests that do not need a device."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import helpers
from helpers import raw_public_key, signed_line
from signer_lab.protocol import parse_response, sha256_file
from signer_lab.receipt import save_receipt
from signer_lab.store import ApprovalStore

CLI = [sys.executable, "-m", "signer_lab"]


class CliTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.file = self.root / "firmware.bin"
        self.file.write_bytes(b"cli test firmware")
        self.receipt = self.root / "approval.json"
        self.database = self.root / "approvals.sqlite3"
        self.key_file = self.root / "public-key.hex"

        self.private = Ed25519PrivateKey.generate()
        self.public = raw_public_key(self.private)
        self.key_file.write_text(self.public.hex() + "\n")

        self.fields = ("a" * 32, sha256_file(self.file), "staging", 4000000000)
        self.response = parse_response(signed_line(self.private, self.fields))
        save_receipt(self.receipt, self.response, trusted_key=self.public)

    def run_cli(self, *arguments):
        env = {"PYTHONPATH": str(helpers.ROOT / "host")}
        return subprocess.run(
            [*CLI, *map(str, arguments)],
            capture_output=True, text=True, timeout=20, env=env,
        )

    def register(self):
        ApprovalStore(self.database).register(
            self.fields[0], self.fields[1], self.fields[2],
            trusted_key=self.public, expires_at=self.fields[3],
        )

    def test_request_prints_canonical_line(self):
        result = self.run_cli(
            "request", self.file, "--target", "staging", "--request-id", "c" * 32
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        parts = result.stdout.strip().split(" ")
        self.assertEqual(parts[:4], ["REQUEST2", "c" * 32, self.fields[1], "staging"])

    def test_verify_with_selected_key(self):
        result = self.run_cli(
            "verify", self.file, "--receipt", self.receipt, "--public-key-file", self.key_file
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("VALID", result.stdout)

    def test_verify_rejects_wrong_key(self):
        other = self.root / "other.hex"
        other.write_text(raw_public_key(Ed25519PrivateKey.generate()).hex())
        result = self.run_cli(
            "verify", self.file, "--receipt", self.receipt, "--public-key-file", other
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("Error:", result.stderr)

    def test_verify_rejects_demo_key_for_foreign_receipt(self):
        result = self.run_cli("verify", self.file, "--receipt", self.receipt, "--allow-demo-key")
        self.assertEqual(result.returncode, 1)

    def test_trust_selection_is_required(self):
        result = self.run_cli("verify", self.file, "--receipt", self.receipt)
        self.assertEqual(result.returncode, 2)
        self.assertIn("required", result.stderr)

    def test_conflicting_trust_options_are_rejected(self):
        result = self.run_cli(
            "verify", self.file, "--receipt", self.receipt,
            "--public-key-file", self.key_file, "--allow-demo-key",
        )
        self.assertEqual(result.returncode, 2)

    def test_accept_consumes_exactly_once(self):
        self.register()
        arguments = (
            "accept", self.file, "--receipt", self.receipt, "--database", self.database,
            "--target", "staging", "--public-key-file", self.key_file,
        )
        first = self.run_cli(*arguments)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertIn("ACCEPTED2", first.stdout)

        second = self.run_cli(*arguments)
        self.assertEqual(second.returncode, 1)
        self.assertIn("already consumed", second.stderr)

    def test_accept_requires_registration(self):
        result = self.run_cli(
            "accept", self.file, "--receipt", self.receipt, "--database", self.database,
            "--target", "staging", "--public-key-file", self.key_file,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("Unknown approval", result.stderr)

    def test_accept_rejects_other_target(self):
        self.register()
        result = self.run_cli(
            "accept", self.file, "--receipt", self.receipt, "--database", self.database,
            "--target", "production", "--public-key-file", self.key_file,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("another target", result.stderr)

    def test_accept_rejects_changed_file(self):
        self.register()
        self.file.write_bytes(b"tampered")
        result = self.run_cli(
            "accept", self.file, "--receipt", self.receipt, "--database", self.database,
            "--target", "staging", "--public-key-file", self.key_file,
        )
        self.assertEqual(result.returncode, 1)
        data = json.loads(self.receipt.read_text())
        self.assertEqual(data["target"], "staging")


if __name__ == "__main__":
    unittest.main()
