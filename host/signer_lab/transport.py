"""Linux serial/PTY transport. Uses only the standard library."""

import os
import select
import termios
import time
import tty

STARTUP_LINE = "Signer firmware started\r\n"


class TransportError(ValueError):
    pass


def _write_all(fd, data, deadline):
    offset = 0
    while offset < len(data):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TransportError("UART write timed out.")
        _, writable, _ = select.select([], [fd], [], remaining)
        if not writable:
            raise TransportError("UART write timed out.")
        try:
            count = os.write(fd, data[offset:])
        except BlockingIOError:
            continue
        if count == 0:
            raise TransportError("UART connection closed.")
        offset += count


def _is_device_notice(line):
    """Lines a (re)starting device prints that answer no command."""
    if line.startswith("BOOT "):
        # Bootloader output. Anything but a successful start means the
        # application will not run and nothing will answer.
        text = line.rstrip("\r\n")
        if text == "BOOT HALT" or (
            text.startswith("BOOT SLOT ") and " OK" not in text
        ):
            raise TransportError("Device did not boot: " + text)
        return True
    return line == STARTUP_LINE or line.startswith(("INFO ", "WARN "))


def _session(port, command, timeout, handle_line, max_line, log):
    """Send `command`, then feed each answer line to `handle_line` until it
    returns something other than None, and return that value."""
    fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    old_settings = None

    try:
        old_settings = termios.tcgetattr(fd)
        tty.setraw(fd)
        termios.tcflush(fd, termios.TCIFLUSH)

        deadline = time.monotonic() + timeout
        _write_all(fd, (command + "\r\n").encode("ascii"), deadline)
        log(f"Sent: {command}", flush=True)

        buffer = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TransportError("Host timed out; firmware result is unknown.")

            readable, _, _ = select.select([fd], [], [], remaining)
            if not readable:
                raise TransportError("Host timed out; firmware result is unknown.")

            try:
                chunk = os.read(fd, 4096)
            except BlockingIOError:
                continue
            if not chunk:
                raise TransportError("UART connection closed.")

            for byte in chunk:
                buffer.append(byte)
                if len(buffer) > max_line:
                    raise TransportError("UART response line is too long.")
                if byte != 10:
                    continue

                line = buffer.decode("ascii")
                buffer.clear()

                if _is_device_notice(line):
                    continue
                if line.startswith("ERR ") or line.startswith("FAULT "):
                    raise TransportError("Firmware: " + line.rstrip("\r\n"))

                result = handle_line(line)
                if result is not None:
                    return result
    finally:
        try:
            if old_settings is not None:
                try:
                    termios.tcsetattr(fd, termios.TCSANOW, old_settings)
                except termios.error as error:
                    # A disconnected PTY cannot restore terminal settings.
                    if error.args[0] not in (5, 6):
                        raise TransportError(
                            "Could not restore UART terminal settings."
                        ) from error
        finally:
            os.close(fd)


def query(port, command, timeout, *, max_line=512, log=print):
    """Send a command that has exactly one answer line, and return it."""
    return _session(port, command, timeout, lambda line: line, max_line, log)


def exchange_command(port, command, timeout, classify, *, max_line=512, log=print):
    """Send one approval request and return the final response line.

    `classify(line)` must return "PENDING" for the intermediate pending
    response and any other value for a final response; it raises
    ValueError for lines that do not belong to this exchange. Exactly one
    PENDING must precede the final response.
    """
    pending_seen = False

    def handle(line):
        nonlocal pending_seen
        kind = classify(line)
        if kind == "PENDING":
            if pending_seen:
                raise TransportError("Repeated PENDING response.")
            pending_seen = True
            log("PENDING: waiting for button approval.", flush=True)
            return None

        if not pending_seen:
            raise TransportError("Final result arrived before PENDING.")

        log("Received: " + line.rstrip("\r\n"), flush=True)
        return line

    return _session(port, command, timeout, handle, max_line, log)
