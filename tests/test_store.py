import sqlite3
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
            "counter": 1,
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
            "counter": 1,
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
                expires_at=200, counter=1, signature=self.signature,
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
            self.request_id, self.digest, self.target, 200, 1
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

    def test_older_protocol_signatures_cannot_approve_v3_request(self):
        for message in (
            f"SIGNER-LAB-V1 {self.request_id} {self.digest}",
            f"SIGNER-LAB-V2 {self.request_id} {self.digest} {self.target} 200",
        ):
            with self.subTest(message=message):
                with self.assertRaisesRegex(ApprovalError, "signature"):
                    self.consume(signature=self.private_key.sign(message.encode("ascii")))
        self.consume()

    def test_signature_with_other_counter_is_rejected(self):
        with self.assertRaisesRegex(ApprovalError, "signature"):
            self.consume(counter=2)
        self.consume()

    def register_and_consume(self, request_id, counter, now=150):
        self.store.register(
            request_id, self.digest, self.target,
            now=100, expires_at=200, trusted_key=self.public_key,
        )
        self.store.consume(
            request_id, self.digest, self.target, now=now, expires_at=200,
            counter=counter,
            signature=self.sign(request_id=request_id, counter=counter),
        )

    def test_counter_must_increase_per_device(self):
        self.consume(counter=5, signature=self.sign(counter=5))
        self.assertEqual(self.store.last_counter(self.public_key), 5)
        for counter in (5, 4):
            with self.subTest(counter=counter):
                with self.assertRaisesRegex(ApprovalError, "not newer"):
                    self.register_and_consume(f"{counter:032x}", counter)
        self.register_and_consume("c" * 32, 6)
        self.assertEqual(self.store.last_counter(self.public_key), 6)

    def test_rejected_counter_leaves_request_pending(self):
        self.consume(counter=5, signature=self.sign(counter=5))
        with self.assertRaisesRegex(ApprovalError, "not newer"):
            self.register_and_consume("d" * 32, 3)
        # The same request can still be accepted with a valid newer counter.
        self.store.consume(
            "d" * 32, self.digest, self.target, now=150, expires_at=200,
            counter=7, signature=self.sign(request_id="d" * 32, counter=7),
        )

    def test_counters_are_tracked_per_device(self):
        self.consume(counter=9, signature=self.sign(counter=9))
        other = Ed25519PrivateKey.generate()
        other_public = other.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )
        self.store.register(
            "e" * 32, self.digest, self.target,
            now=100, expires_at=200, trusted_key=other_public,
        )
        message = approval_message("e" * 32, self.digest, self.target, 200, 1)
        self.store.consume(
            "e" * 32, self.digest, self.target, now=150, expires_at=200,
            counter=1, signature=other.sign(message),
        )
        self.assertEqual(self.store.last_counter(other_public), 1)
        self.assertEqual(self.store.last_counter(self.public_key), 9)

    def test_invalid_counter_values_are_rejected(self):
        for counter in (0, -1, 2**32 - 1, True, "1"):
            with self.subTest(counter=counter):
                with self.assertRaises(ApprovalError):
                    self.consume(counter=counter)
        self.consume()

    def test_old_schema_is_refused(self):
        old = Path(self.path).with_name("old.sqlite3")
        connection = sqlite3.connect(old)
        connection.execute(
            "CREATE TABLE approvals (request_id TEXT PRIMARY KEY, trusted_key BLOB)"
        )
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(ApprovalError, "Old database schema"):
            ApprovalStore(old)


if __name__ == "__main__":
    unittest.main()
