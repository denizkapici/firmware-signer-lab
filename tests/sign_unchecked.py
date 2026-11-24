"""Sign an application binary into a slot image WITHOUT the vector-table
check that 'signer-lab firmware sign' performs. Tests only: it produces
correctly signed but unbootable images."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "host"))

from signer_lab import firmware_image  # noqa: E402

application, key, out = sys.argv[1:]
image = firmware_image.build_image(
    Path(application).read_bytes(), 1, firmware_image.load_private_key(key)
)
Path(out).write_bytes(image)
