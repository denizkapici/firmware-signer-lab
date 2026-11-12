import importlib.util
import tempfile
import unittest
from pathlib import Path

MODULE = (
    Path(__file__).resolve().parents[1]
    / "scripts" / "signer_key_policy.py"
)
SPEC = importlib.util.spec_from_file_location("signer_key_policy", MODULE)
policy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(policy)


class KeyPolicyTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "public-key.hex"

    def test_missing_trust_is_rejected(self):
        with self.assertRaises(ValueError):
            policy.load_trusted_key()

    def test_explicit_demo_is_accepted(self):
        key = policy.load_trusted_key(allow_demo_key=True)
        self.assertEqual(key, policy.DEMO_PUBLIC_KEY)
        self.assertEqual(policy.key_id(key), "RFC8032-TEST1-DEMO")

    def test_conflicting_options_are_rejected(self):
        with self.assertRaises(ValueError):
            policy.load_trusted_key(self.path, allow_demo_key=True)

    def test_demo_key_file_cannot_bypass_explicit_selection(self):
        self.path.write_text(policy.DEMO_PUBLIC_KEY.hex())
        with self.assertRaisesRegex(ValueError, "allow-demo-key"):
            policy.load_trusted_key(self.path)

    def test_public_key_file_is_loaded(self):
        # RFC 8032 TEST 2 public key; no private key is needed.
        text = (
            "3d4017c3e843895a92b70aa74d1b7ebc"
            "9c982ccf2ec4968cc0cd55f12af4660c"
        )
        self.path.write_text(text.upper() + "\n")
        key = policy.load_trusted_key(self.path)
        self.assertEqual(key.hex(), text)
        self.assertTrue(policy.key_id(key).startswith("ED25519-SHA256-"))
        self.assertNotEqual(policy.key_id(key), policy.DEMO_KEY_ID)

    def test_malformed_key_files_are_rejected(self):
        for text in ("", "ab" * 31, "ab" * 33, "gg" * 32, "{}"):
            with self.subTest(text=text):
                self.path.write_text(text)
                with self.assertRaises(ValueError):
                    policy.load_trusted_key(self.path)

    def test_missing_file_is_rejected(self):
        with self.assertRaises(FileNotFoundError):
            policy.load_trusted_key(self.path)


if __name__ == "__main__":
    unittest.main()
