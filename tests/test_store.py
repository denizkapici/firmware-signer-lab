import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import helpers  # noqa: F401  (makes signer_lab importable)
from signer_lab.protocol import approval_message
from signer_lab.store import ApprovalError, ApprovalStore


class ApprovalStoreTests(unittest.TestCase):
    request_id = "a" * 32
    digest = "b" * 64
    target = "staging"

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "approvals.sqlite3"
        self.store = ApprovalStore(self.path)
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        self.signature = self.sign()
        self.store.register(
            self.request_id, self.digest, self.target,
            now=100, expires_at=200, trusted_key=self.public_key,
        )

    def sign(self, **changes):
        fields = {
            "request_id": self.request_id,
            "digest": self.digest,
            "target": self.target,
            "expires_at": 200,
        }
        fields.update(changes)
        return self.private_key.sign(approval_message(**fields))

    def consume(self, **changes):
        values = {
            "request_id": self.request_id,
            "digest": self.digest,
            "target": self.target,
            "now": 150,
            "expires_at": 200,
            "signature": self.signature,
        }
        values.update(changes)
        self.store.consume(**values)

    def test_approval_can_only_be_consumed_once(self):
        self.consume()
        with self.assertRaises(ApprovalError):
            self.consume()

    def test_consumption_survives_reopening(self):
        self.consume()
        reopened = ApprovalStore(self.path)
        with self.assertRaises(ApprovalError):
            reopened.consume(
                self.request_id, self.digest, self.target, now=151,
                expires_at=200, signature=self.signature,
            )

    def test_expired_approval_is_rejected(self):
        for now in (200, 201):
            with self.subTest(now=now):
                with self.assertRaises(ApprovalError):
                    self.consume(now=now)

    def test_time_before_creation_is_rejected(self):
        with self.assertRaises(ApprovalError):
            self.consume(now=99)

    def test_wrong_binding_does_not_consume_correct_request(self):
        for changes in (
            {"request_id": "c" * 32},
            {"digest": "d" * 64},
            {"target": "production"},
        ):
            with self.subTest(changes=changes):
                with self.assertRaises(ApprovalError):
                    self.consume(**changes)
        self.consume()

    def test_duplicate_registration_cannot_reset_consumed_request(self):
        self.consume()
        with self.assertRaises(ApprovalError):
            self.store.register(
                self.request_id, self.digest, self.target,
                now=150, expires_at=300, trusted_key=self.public_key,
            )
        with self.assertRaises(ApprovalError):
            self.consume(now=160)

    def test_concurrent_consumers_have_exactly_one_winner(self):
        barrier = threading.Barrier(2)

        def attempt():
            barrier.wait(timeout=5)
            try:
                self.consume()
                return True
            except ApprovalError:
                return False

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(attempt) for _ in range(2)]
            results = [future.result(timeout=15) for future in futures]

        self.assertEqual(sorted(results), [False, True])

    def test_invalid_registration_is_rejected(self):
        for changes in (
            {"request_id": "short"},
            {"digest": "invalid"},
            {"target": "../production"},
            {"expires_at": 100},
            {"expires_at": float("nan")},
        ):
            values = {
                "request_id": "e" * 32,
                "digest": self.digest,
                "target": self.target,
                "now": 100,
                "expires_at": 200,
                "trusted_key": self.public_key,
            }
            values.update(changes)
            with self.subTest(changes=changes):
                with self.assertRaises(ApprovalError):
                    self.store.register(**values)



    def test_invalid_signature_does_not_consume_request(self):
        damaged = bytearray(self.signature)
        damaged[0] ^= 1
        with self.assertRaisesRegex(ApprovalError, "signature"):
            self.consume(signature=bytes(damaged))
        self.consume()

    def test_other_key_cannot_approve_registered_request(self):
        other_key = Ed25519PrivateKey.generate()
        message = approval_message(
            self.request_id, self.digest, self.target, 200
        )
        with self.assertRaisesRegex(ApprovalError, "signature"):
            self.consume(signature=other_key.sign(message))
        self.consume()

    def test_valid_signature_with_changed_expiry_is_rejected(self):
        with self.assertRaises(ApprovalError):
            self.consume(
                expires_at=300,
                signature=self.sign(expires_at=300),
            )
        self.consume()

    def test_valid_signature_for_other_target_is_rejected(self):
        with self.assertRaises(ApprovalError):
            self.consume(
                target="production",
                signature=self.sign(target="production"),
            )
        self.consume()

    def test_v1_signature_cannot_approve_v2_request(self):
        message = (
            f"SIGNER-LAB-V1 {self.request_id} {self.digest}"
        ).encode("ascii")
        with self.assertRaisesRegex(ApprovalError, "signature"):
            self.consume(signature=self.private_key.sign(message))
        self.consume()


if __name__ == "__main__":
    unittest.main()
