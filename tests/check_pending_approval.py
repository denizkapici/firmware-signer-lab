"""Check that a timeout left one approval pending and unconsumed."""

import sqlite3
import sys
from contextlib import closing
from pathlib import Path

path = Path(sys.argv[1]).resolve()

# Read-only mode also prevents silently creating a missing database.
with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as connection:
    rows = connection.execute(
        "SELECT state, consumed_at, counter FROM approvals"
    ).fetchall()

if rows != [("pending", None, None)]:
    raise SystemExit(f"Unexpected approval state: {rows!r}")

print("PASS: approval remains pending and unconsumed.")
