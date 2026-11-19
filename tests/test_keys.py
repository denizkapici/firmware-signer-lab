import hashlib
import tempfile
import unittest
from pathlib import Path

import helpers  # noqa: F401
from signer_lab import keys

# RFC 8032 TEST 2 public key; no private key is needed.
TEST2 = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"


class KeyPolicyTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "public-key.hex"

    def test_key_file_is_required(self):
        with self.assertRaisesRegex(ValueError, "required"):
            keys.load_trusted_key(None)

    def test_public_key_file_is_loaded(self):
        self.path.write_text(TEST2.upper() + "\n")
        key = keys.load_trusted_key(self.path)
        self.assertEqual(key.hex(), TEST2)
        expected = "ED25519-SHA256-" + hashlib.sha256(key).hexdigest()
        self.assertEqual(keys.key_id(key), expected)

    def test_demo_key_is_never_trusted(self):
        self.path.write_text(keys.DEMO_PUBLIC_KEY.hex())
        with self.assertRaisesRegex(ValueError, "RFC 8032"):
            keys.load_trusted_key(self.path)

    def test_blank_keys_are_rejected(self):
        for text in ("00" * 32, "ff" * 32):
            with self.subTest(text=text):
                with self.assertRaisesRegex(ValueError, "blank"):
                    keys.parse_public_key(text)

    def test_malformed_key_files_are_rejected(self):
        for text in ("", "ab" * 31, "ab" * 33, "gg" * 32, "{}"):
            with self.subTest(text=text):
                self.path.write_text(text)
                with self.assertRaises(ValueError):
                    keys.load_trusted_key(self.path)

    def test_missing_file_is_rejected(self):
        with self.assertRaises(FileNotFoundError):
            keys.load_trusted_key(self.path)

    def test_saved_key_round_trips_and_is_not_overwritten(self):
        key = bytes.fromhex(TEST2)
        keys.save_public_key(self.path, key)
        self.assertEqual(keys.load_trusted_key(self.path), key)
        with self.assertRaises(FileExistsError):
            keys.save_public_key(self.path, bytes(range(32)))
        self.assertEqual(keys.load_trusted_key(self.path), key)


if __name__ == "__main__":
    unittest.main()
