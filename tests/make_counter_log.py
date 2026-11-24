"""Write a 16 KB counter-log sector image for Renode tests.

    make_counter_log.py OUT first last        valid entries first..last
    make_counter_log.py OUT first last torn   ... followed by one torn entry

Each entry is the value and its bitwise complement (little endian); the
rest of the sector is erased (0xFF)."""

import struct
import sys

SECTOR = 16 * 1024

out, first, last, *extra = sys.argv[1:]
data = bytearray()
for value in range(int(first), int(last) + 1):
    data += struct.pack("<II", value, value ^ 0xFFFFFFFF)
if extra == ["torn"]:
    # Large value with a wrong complement: must be ignored by the firmware.
    data += struct.pack("<II", 0x7FFFFFFF, 0x12345678)
if len(data) > SECTOR:
    raise SystemExit("Too many entries for one sector.")
data += b"\xff" * (SECTOR - len(data))

with open(out, "wb") as stream:
    stream.write(data)
