import importlib.util
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "signer-client.py"
SPEC = importlib.util.spec_from_file_location("signer_client", SCRIPT)
client = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(client)


class SignerClientTests(unittest.TestCase):
    request_id = "A0000001"
    digest = "a" * 64

    def test_known_file_hash(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "sample.bin"
            path.write_bytes(b"abc")
            self.assertEqual(
                client.sha256_file(path),
                "ba7816bf8f01cfea414140de5dae2223"
                "b00361a396177a9cb410ff61f20015ad",
            )

    def test_request_format_and_length(self):
        request = client.build_request(self.request_id, self.digest)
        self.assertEqual(request, f"REQUEST {self.request_id} {self.digest}")
        self.assertEqual(len(request), 81)

    def test_invalid_request_values(self):
        for request_id, digest in [
            ("ABC", self.digest),
            ("Z0000001", self.digest),
            (self.request_id, "a" * 63),
            (self.request_id, "g" * 64),
        ]:
            with self.subTest(request_id=request_id, digest=digest):
                with self.assertRaises(ValueError):
                    client.build_request(request_id, digest)

    def test_matching_approval(self):
        result = client.validate_response(
            f"APPROVED {self.request_id} {self.digest}\r\n",
            self.request_id,
            self.digest,
        )
        self.assertEqual(result, "APPROVED")

    def test_other_request_is_rejected(self):
        with self.assertRaises(ValueError):
            client.validate_response(
                f"APPROVED B0000002 {self.digest}",
                self.request_id,
                self.digest,
            )

    def test_changed_digest_is_rejected(self):
        with self.assertRaises(ValueError):
            client.validate_response(
                f"APPROVED {self.request_id} {'b' * 64}",
                self.request_id,
                self.digest,
            )

    def test_nonapproval_states_remain_distinct(self):
        for status in ("PENDING", "CANCELLED", "TIMEOUT"):
            with self.subTest(status=status):
                result = client.validate_response(
                    f"{status} {self.request_id} {self.digest}",
                    self.request_id,
                    self.digest,
                )
                self.assertEqual(result, status)
                self.assertNotEqual(result, "APPROVED")

    def test_malformed_responses_are_rejected(self):
        for line in (
            "APPROVED",
            f"UNKNOWN {self.request_id} {self.digest}",
            f"APPROVED  {self.request_id} {self.digest}",
            f"APPROVED {self.request_id} {self.digest} extra",
            f"APPROVED {self.request_id} {self.digest}\nextra",
        ):
            with self.subTest(line=line):
                with self.assertRaises(ValueError):
                    client.validate_response(
                        line, self.request_id, self.digest
                    )


if __name__ == "__main__":
    unittest.main()
