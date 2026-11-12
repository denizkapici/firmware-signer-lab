import contextlib
import io
import os
import pty
import select
import threading
import time
import unittest

from test_signer_client import client, signed_response


class TransportTests(unittest.TestCase):
    request_id = "A0000001"
    digest = "a" * 64

    def exchange(self, responses, timeout=2.0):
        master, slave = pty.openpty()
        port = os.ttyname(slave)
        errors = []
        expected = (
            f"REQUEST {self.request_id} {self.digest}\r\n"
        ).encode("ascii")

        def peer():
            try:
                received = bytearray()
                deadline = time.monotonic() + 3.0

                while b"\n" not in received:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise AssertionError("Client did not send a request.")

                    readable, _, _ = select.select(
                        [master], [], [], remaining
                    )
                    if not readable:
                        raise AssertionError("Client request timed out.")

                    received.extend(os.read(master, 4096))

                self.assertEqual(bytes(received), expected)

                for response in responses:
                    payload = response.encode("ascii")
                    offset = 0
                    while offset < len(payload):
                        offset += os.write(master, payload[offset:])
                    time.sleep(0.005)
            except BaseException as error:
                errors.append(error)

        worker = threading.Thread(target=peer, daemon=True)
        worker.start()

        try:
            with contextlib.redirect_stdout(io.StringIO()):
                return client.exchange_uart(
                    port, self.request_id, self.digest, timeout, trusted_key=client.DEMO_PUBLIC_KEY
                )
        finally:
            worker.join(timeout=4.0)
            os.close(slave)
            os.close(master)

            if worker.is_alive():
                raise AssertionError("PTY test worker did not finish.")
            if errors:
                raise errors[0]

    def test_fragmented_approval_response(self):
        pending = f"PENDING {self.request_id} {self.digest}\r\n"
        approved = signed_response(self.request_id, self.digest) + "\r\n"

        result = self.exchange([
            pending[:9],
            pending[9:],
            approved[:4],
            approved[4:30],
            approved[30:],
        ])

        self.assertEqual(result, approved)

    def test_wrong_digest_from_uart_is_rejected(self):
        pending = f"PENDING {self.request_id} {self.digest}\r\n"
        wrong = signed_response(self.request_id, "b" * 64) + "\r\n"

        with self.assertRaisesRegex(ValueError, "ozet"):
            self.exchange([pending + wrong])

    def test_final_result_without_pending_is_rejected(self):
        approved = signed_response(self.request_id, self.digest) + "\r\n"

        with self.assertRaisesRegex(ValueError, "PENDING alinmadan"):
            self.exchange([approved])

    def test_duplicate_pending_is_rejected(self):
        pending = f"PENDING {self.request_id} {self.digest}\r\n"

        with self.assertRaisesRegex(ValueError, "Tekrarlanan PENDING"):
            self.exchange([pending + pending])

    def test_silent_peer_causes_host_timeout(self):
        with self.assertRaisesRegex(ValueError, "Host bekleme suresi"):
            self.exchange([], timeout=0.5)


if __name__ == "__main__":
    unittest.main()
