import os
import pty
import select
import threading
import time
import unittest

import helpers
from helpers import fields_text, signed_line
from signer_lab.keys import DEMO_PUBLIC_KEY
from signer_lab.protocol import Operation, check_response
from signer_lab.transport import exchange_command, query

FIELDS = ("a" * 32, "b" * 64, "staging", 1800000000)
OPERATION = Operation(*FIELDS)
PENDING = f"PENDING3 {fields_text(FIELDS)}\r\n"
APPROVED = signed_line(helpers.demo_private_key(), FIELDS) + "\r\n"


def classify(line):
    status = check_response(line, OPERATION, DEMO_PUBLIC_KEY).status
    return "PENDING" if status == "PENDING3" else status


class TransportTests(unittest.TestCase):
    def exchange(self, responses, timeout=2.0):
        master, slave = pty.openpty()
        port = os.ttyname(slave)
        errors = []
        expected = (OPERATION.request_line() + "\r\n").encode("ascii")

        def peer():
            try:
                received = bytearray()
                deadline = time.monotonic() + 3.0
                while b"\n" not in received:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise AssertionError("Client did not send a request.")
                    readable, _, _ = select.select([master], [], [], remaining)
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
            except BaseException as error:  # reported in the main thread
                errors.append(error)

        worker = threading.Thread(target=peer, daemon=True)
        worker.start()
        try:
            return exchange_command(
                port, OPERATION.request_line(), timeout, classify,
                log=lambda *args, **kwargs: None,
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
        result = self.exchange([
            PENDING[:9], PENDING[9:], APPROVED[:4], APPROVED[4:30], APPROVED[30:],
        ])
        self.assertEqual(result, APPROVED)

    def test_startup_and_warning_lines_are_ignored(self):
        result = self.exchange([
            "WARN WATCHDOG_RESET\r\n", "INFO KEY_LOADED\r\n",
            "Signer firmware started\r\n", PENDING, APPROVED,
        ])
        self.assertEqual(result, APPROVED)

    def test_bootloader_success_lines_are_ignored(self):
        result = self.exchange([
            "BOOT signer-lab bootloader\r\n", "BOOT SLOT A OK version=3\r\n",
            "Signer firmware started\r\n", PENDING, APPROVED,
        ])
        self.assertEqual(result, APPROVED)

    def test_failed_boot_is_reported(self):
        for line in ("BOOT SLOT A BAD_SIGNATURE\r\n", "BOOT HALT\r\n"):
            with self.subTest(line=line):
                with self.assertRaisesRegex(ValueError, "Device did not boot"):
                    self.exchange([line])

    def test_firmware_fault_is_reported(self):
        with self.assertRaisesRegex(ValueError, "Firmware: FAULT"):
            self.exchange([PENDING, "FAULT pc=08000100 lr=00000000\r\n"])

    def test_firmware_error_is_reported(self):
        with self.assertRaisesRegex(ValueError, "Firmware: ERR BUSY"):
            self.exchange(["ERR BUSY\r\n"])

    def test_wrong_digest_from_uart_is_rejected(self):
        wrong = signed_line(helpers.demo_private_key(), ("a" * 32, "c" * 64, "staging", 1800000000))
        with self.assertRaisesRegex(ValueError, "does not match"):
            self.exchange([PENDING + wrong + "\r\n"])

    def test_final_result_without_pending_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "before PENDING"):
            self.exchange([APPROVED])

    def test_duplicate_pending_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Repeated PENDING"):
            self.exchange([PENDING + PENDING])

    def test_overlong_line_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "too long"):
            self.exchange(["x" * 600 + "\r\n"])

    def test_silent_peer_causes_host_timeout(self):
        with self.assertRaisesRegex(ValueError, "timed out"):
            self.exchange([], timeout=0.5)


class QueryTests(unittest.TestCase):
    def test_query_returns_first_answer_after_notices(self):
        master, slave = pty.openpty()

        def device():
            os.read(master, 64)
            os.write(master, b"INFO KEY_GENERATED\r\nPUBKEY " + b"ab" * 32 + b"\r\n")

        worker = threading.Thread(target=device, daemon=True)
        worker.start()
        try:
            line = query(os.ttyname(slave), "PUBKEY", 2.0, log=lambda *a, **k: None)
        finally:
            worker.join(timeout=3)
            os.close(slave)
            os.close(master)
        self.assertEqual(line, "PUBKEY " + "ab" * 32 + "\r\n")


if __name__ == "__main__":
    unittest.main()
