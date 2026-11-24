"""Verify a V3 signature before atomically consuming a registered approval.

Besides single use per request ID, the store keeps the highest device
counter accepted for each trusted key and refuses any approval whose
counter is not larger. The device never signs two approvals with the same
counter, so this rejects reordered or replayed approvals from that device.
The high-water mark lives in this database too: restoring an old copy of
the database restores an old mark (see docs/threat-model.md, T7).
"""

import math
import sqlite3
import time
from contextlib import closing

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .protocol import approval_message, validate_counter, validate_fields


class ApprovalError(ValueError):
    pass


def validate_time(value):
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < 0
    ):
        raise ApprovalError("Invalid timestamp.")


class ApprovalStore:
    def __init__(self, path):
        self.path = str(path)
        with closing(self.connect()) as connection, connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS approvals (
                    request_id TEXT PRIMARY KEY,
                    digest TEXT NOT NULL,
                    target TEXT NOT NULL,
                    trusted_key BLOB NOT NULL CHECK(length(trusted_key) = 32),
                    created_at REAL NOT NULL,
                    expires_at INTEGER NOT NULL,
                    consumed_at REAL,
                    state TEXT NOT NULL CHECK(state IN ('pending', 'consumed')),
                    counter INTEGER CHECK(counter BETWEEN 1 AND 4294967294),
                    CHECK(expires_at > created_at),
                    CHECK((state = 'consumed') = (counter IS NOT NULL)),
                    UNIQUE(trusted_key, counter)
                )
            """)
            connection.execute("""
                CREATE TABLE IF NOT EXISTS device_counters (
                    trusted_key BLOB PRIMARY KEY CHECK(length(trusted_key) = 32),
                    last_counter INTEGER NOT NULL
                        CHECK(last_counter BETWEEN 1 AND 4294967294)
                )
            """)
            columns = {
                row[1] for row in connection.execute("PRAGMA table_info(approvals)")
            }
            if not {"trusted_key", "counter"} <= columns:
                raise ApprovalError(
                    "Old database schema (before V3): use a new database file."
                )

    def connect(self):
        return sqlite3.connect(self.path, timeout=10)

    def register(
        self, request_id, digest, target, *,
        trusted_key, expires_at, now=None,
    ):
        try:
            validate_fields(request_id, digest, target, expires_at)
        except ValueError as error:
            raise ApprovalError(str(error)) from error

        if not isinstance(trusted_key, bytes) or len(trusted_key) != 32:
            raise ApprovalError("Trusted public key must be 32 bytes.")

        now = time.time() if now is None else now
        validate_time(now)
        if expires_at <= now:
            raise ApprovalError("Expiry must be after creation.")

        try:
            with closing(self.connect()) as connection, connection:
                connection.execute("""
                    INSERT INTO approvals (
                        request_id, digest, target, trusted_key,
                        created_at, expires_at, state
                    ) VALUES (?, ?, ?, ?, ?, ?, 'pending')
                """, (
                    request_id, digest, target, trusted_key,
                    now, expires_at,
                ))
        except sqlite3.IntegrityError as error:
            raise ApprovalError("Request ID already registered.") from error

    def last_counter(self, trusted_key):
        """Highest counter accepted from this key, or 0."""
        with closing(self.connect()) as connection:
            row = connection.execute(
                "SELECT last_counter FROM device_counters WHERE trusted_key = ?",
                (trusted_key,),
            ).fetchone()
        return 0 if row is None else row[0]

    def consume(
        self, request_id, digest, target, *,
        expires_at, counter, signature, now=None,
    ):
        try:
            validate_counter(counter)
            message = approval_message(request_id, digest, target, expires_at, counter)
        except ValueError as error:
            raise ApprovalError(str(error)) from error

        if not isinstance(signature, bytes) or len(signature) != 64:
            raise ApprovalError("Signature must be 64 bytes.")

        with closing(self.connect()) as connection, connection:
            # Serialize competing consumers before reading the pending record.
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("""
                SELECT digest, target, expires_at, trusted_key, created_at, state
                FROM approvals WHERE request_id = ?
            """, (request_id,)).fetchone()

            if row is None:
                raise ApprovalError("Unknown approval.")

            stored_digest, stored_target, expiry, key, created, state = row
            if (
                stored_digest != digest
                or stored_target != target
                or expiry != expires_at
                or state != "pending"
            ):
                raise ApprovalError("Mismatched or already consumed approval.")

            try:
                Ed25519PublicKey.from_public_bytes(key).verify(signature, message)
            except (InvalidSignature, ValueError) as error:
                raise ApprovalError("Invalid approval signature.") from error

            # Read the real clock after lock acquisition and signature checking.
            # Explicit 'now' is provided only for deterministic tests.
            checked_at = time.time() if now is None else now
            validate_time(checked_at)
            if checked_at < created or checked_at >= expiry:
                raise ApprovalError("Approval is outside its validity period.")

            last = connection.execute(
                "SELECT last_counter FROM device_counters WHERE trusted_key = ?",
                (key,),
            ).fetchone()
            if last is not None and counter <= last[0]:
                raise ApprovalError(
                    f"Approval counter {counter} is not newer than the last "
                    f"accepted counter {last[0]} from this device."
                )

            cursor = connection.execute("""
                UPDATE approvals
                SET state = 'consumed', consumed_at = ?, counter = ?
                WHERE request_id = ? AND state = 'pending'
            """, (checked_at, counter, request_id))
            if cursor.rowcount != 1:
                raise ApprovalError("Approval could not be consumed.")

            connection.execute("""
                INSERT INTO device_counters (trusted_key, last_counter) VALUES (?, ?)
                ON CONFLICT(trusted_key) DO UPDATE SET last_counter = excluded.last_counter
            """, (key, counter))
