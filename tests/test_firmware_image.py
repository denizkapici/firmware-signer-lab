"""Firmware image format: the Python signing tool and the bootloader's C
verification code (firmware/boot/image.c built for the host) must agree."""

import ctypes
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import helpers
from signer_lab import firmware_image as fw

ROOT = helpers.ROOT
SLOT = fw.SLOT_A_ADDRESS
CODE = SLOT + fw.HEADER_SIZE

# Minimal "application": initial SP at the top of RAM, entry inside the image.
APPLICATION = struct.pack("<II", 0x20020000, CODE + 0x41) + bytes(range(256)) * 4

STATUS = {0: "OK", 1: "EMPTY", 2: "BAD_HEADER", 3: "BAD_SIZE",
          4: "BAD_SIGNATURE", 5: "BAD_VECTORS"}


class ImageInfo(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint32)
                for name in ("version", "size", "stack_pointer", "entry")]


def application(stack_pointer=0x20020000, entry=CODE + 0x41):
    return struct.pack("<II", stack_pointer, entry) + APPLICATION[8:]


class FirmwareImageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(directory.cleanup)
        cls.directory = Path(directory.name)
        library = cls.directory / "image.so"
        subprocess.run([
            "gcc", "-shared", "-fPIC", "-std=c11", "-O2",
            "-Wall", "-Wextra", "-Werror",
            "-Ifirmware/boot", "-Ifirmware/vendor/monocypher",
            "firmware/boot/image.c",
            "firmware/vendor/monocypher/monocypher.c",
            "firmware/vendor/monocypher/monocypher-ed25519.c",
            "-o", str(library),
        ], cwd=ROOT, check=True)
        cls.library = ctypes.CDLL(str(library))
        cls.library.image_verify.argtypes = [
            ctypes.c_char_p, ctypes.c_uint32, ctypes.c_uint32,
            ctypes.c_char_p, ctypes.POINTER(ImageInfo),
        ]
        cls.library.image_verify.restype = ctypes.c_int

    def setUp(self):
        self.private = Ed25519PrivateKey.generate()
        self.public = fw.public_key_bytes(self.private)

    def c_verify(self, image, public=None, slot_size=fw.SLOT_SIZE):
        # The bootloader reads a whole slot: pad like erased flash.
        slot = bytes(image) + b"\xff" * (slot_size - len(image))
        info = ImageInfo()
        status = self.library.image_verify(
            slot, SLOT, slot_size, public or self.public, ctypes.byref(info)
        )
        return STATUS[status], info

    def assert_both_reject(self, image, c_status, public=None):
        self.assertEqual(self.c_verify(image, public)[0], c_status)
        with self.assertRaises(ValueError):
            fw.verify_image(image, public or self.public)

    def test_valid_image_is_accepted_by_both(self):
        image = fw.build_image(APPLICATION, 7, self.private)
        info = fw.verify_image(image, self.public)
        status, c_info = self.c_verify(image)
        self.assertEqual(status, "OK")
        self.assertEqual((c_info.version, c_info.size, c_info.stack_pointer, c_info.entry),
                         (info.version, info.size, info.stack_pointer, info.entry))
        self.assertEqual(info.version, 7)

    def test_layout(self):
        image = fw.build_image(APPLICATION, 3, self.private)
        magic, header_version, size, version = struct.unpack_from("<IIII", image)
        self.assertEqual((magic, header_version, size, version),
                         (0x49574653, 1, len(APPLICATION), 3))
        self.assertEqual(image[16:64], bytes(48))
        self.assertEqual(image[128:0x200], b"\xff" * (0x200 - 128))
        self.assertEqual(image[0x200:], APPLICATION)

    def test_application_is_padded_to_words(self):
        image = fw.build_image(APPLICATION + b"\x01", 1, self.private)
        self.assertEqual(len(image) % 4, 0)
        self.assertEqual(self.c_verify(image)[0], "OK")

    def test_any_changed_byte_is_rejected(self):
        image = fw.build_image(APPLICATION, 1, self.private)
        for offset in (12, 64, 100, 0x200, 0x200 + 300, len(image) - 1):
            with self.subTest(offset=offset):
                changed = bytearray(image)
                changed[offset] ^= 1
                c_status = self.c_verify(bytes(changed))[0]
                self.assertIn(c_status, ("BAD_SIGNATURE", "BAD_SIZE", "BAD_HEADER"))
                with self.assertRaises(ValueError):
                    fw.verify_image(bytes(changed), self.public)

    def test_padding_after_signature_is_not_signed(self):
        # Bytes 0x80..0x1FF are padding; changing them must not matter.
        image = bytearray(fw.build_image(APPLICATION, 1, self.private))
        image[0x150] = 0
        self.assertEqual(self.c_verify(bytes(image))[0], "OK")
        fw.verify_image(bytes(image), self.public)

    def test_other_key_is_rejected(self):
        image = fw.build_image(APPLICATION, 1, Ed25519PrivateKey.generate())
        self.assert_both_reject(image, "BAD_SIGNATURE")

    def test_empty_and_bad_headers(self):
        self.assertEqual(self.c_verify(b"\xff" * fw.HEADER_SIZE)[0], "EMPTY")
        self.assertEqual(self.c_verify(bytes(fw.HEADER_SIZE))[0], "BAD_HEADER")
        image = bytearray(fw.build_image(APPLICATION, 1, self.private))
        image[4] = 2  # header version
        self.assert_both_reject(bytes(image), "BAD_HEADER")
        image = bytearray(fw.build_image(APPLICATION, 1, self.private))
        image[40] = 1  # reserved
        self.assert_both_reject(bytes(image), "BAD_HEADER")

    def test_size_is_bounded_by_the_slot(self):
        image = bytearray(fw.build_image(APPLICATION, 1, self.private))
        for size in (0, 6, fw.SLOT_SIZE - fw.HEADER_SIZE + 4, 0xFFFFFFFC):
            with self.subTest(size=size):
                struct.pack_into("<I", image, 8, size)
                self.assertEqual(self.c_verify(bytes(image))[0], "BAD_SIZE")
        with self.assertRaises(ValueError):
            fw.build_image(bytes(fw.SLOT_SIZE), 1, self.private)

    def test_signed_image_with_bad_vectors_is_rejected(self):
        for stack_pointer, entry in (
            (0x20020000, CODE + 0x40),          # Thumb bit clear
            (0x20020000, 0x08000001),           # entry in the bootloader
            (0x20020000, CODE + len(APPLICATION) + 1),  # entry past the image
            (0x08000000, CODE + 0x41),          # stack not in RAM
            (0x20020004, CODE + 0x41),          # stack above RAM
            (0x2001FFFC, CODE + 0x41),          # stack not 8-byte aligned
        ):
            with self.subTest(sp=hex(stack_pointer), entry=hex(entry)):
                image = fw.build_image(application(stack_pointer, entry), 1, self.private)
                self.assert_both_reject(image, "BAD_VECTORS")

    def test_invalid_versions_are_refused_when_signing(self):
        for version in (-1, 2**32, True, "1"):
            with self.subTest(version=version):
                with self.assertRaises(ValueError):
                    fw.build_image(APPLICATION, version, self.private)

    def test_key_files(self):
        key = self.directory / f"key-{id(self)}.hex"
        public = fw.generate_key(key)
        self.assertEqual(key.stat().st_mode & 0o777, 0o600)
        self.assertEqual(fw.public_key_bytes(fw.load_private_key(key)), public)
        with self.assertRaises(FileExistsError):
            fw.generate_key(key)
        header = fw.public_key_c_header(public)
        self.assertIn("firmware_public_key[32]", header)
        self.assertEqual(header.count("0x"), 32)


if __name__ == "__main__":
    unittest.main()
