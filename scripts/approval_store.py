"""Persistent single-use state. Call consume only after signature verification."""

from contextlib import closing
import math
import re
import sqlite3


class ApprovalError(ValueError):
    pass


def validate_binding(request_id, digest, target):
    if not isinstance(request_id, str) or not re.fullmatch(
        r"[0-9a-f]{32}", request_id
    ):
        raise ApprovalError("Request ID must be 32 lowercase hexadecimal characters.")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ApprovalError("Digest must be 64 lowercase hexadecimal characters.")
    if not isinstance(target, str) or not re.fullmatch(
        r"[a-z0-9][a-z0-9_-]{0,31}", target
    ):
        raise ApprovalError("Invalid target.")


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
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    consumed_at REAL,
                    state TEXT NOT NULL CHECK(state IN ('pending', 'consumed')),
                    CHECK(expires_at > created_at)
                )
            """)

    def connect(self):
        return sqlite3.connect(self.path, timeout=10)

    def register(self, request_id, digest, target, *, now, expires_at):
        validate_binding(request_id, digest, target)
        validate_time(now)
        validate_time(expires_at)
        if expires_at <= now:
            raise ApprovalError("Expiry must be after creation.")

        connection = self.connect()
        try:
            with connection:
                connection.execute("""
                    INSERT INTO approvals (
                        request_id, digest, target, created_at, expires_at, state
                    ) VALUES (?, ?, ?, ?, ?, 'pending')
                """, (request_id, digest, target, now, expires_at))
        except sqlite3.IntegrityError as error:
            raise ApprovalError("Request ID already registered.") from error
        finally:
            connection.close()

    def consume(self, request_id, digest, target, *, now):
        validate_binding(request_id, digest, target)
        validate_time(now)

        connection = self.connect()
        try:
            with connection:
                # One conditional UPDATE makes the state transition atomic.
                cursor = connection.execute("""
                    UPDATE approvals
                    SET state = 'consumed', consumed_at = ?
                    WHERE request_id = ?
                      AND digest = ?
                      AND target = ?
                      AND state = 'pending'
                      AND created_at <= ?
                      AND expires_at > ?
                """, (now, request_id, digest, target, now, now))

                if cursor.rowcount != 1:
                    raise ApprovalError(
                        "Unknown, mismatched, expired, or already consumed approval."
                    )
        finally:
            connection.close()
