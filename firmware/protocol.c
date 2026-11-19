#include "protocol.h"

#include "approval.h"
#include "gpio.h"
#include "uart.h"

enum line_error {
    LINE_OK = 0,
    LINE_TOO_LONG,
    LINE_INVALID_CHARACTER,
    LINE_RX_OVERFLOW
};

static char line[PROTOCOL_MAX_LINE + 1u];
static uint32_t length;
static enum line_error error;

static int text_equal(const char *left, const char *right)
{
    while (*left != '\0' && *left == *right) {
        ++left;
        ++right;
    }
    return *left == *right;
}

static int text_starts_with(const char *text, const char *prefix)
{
    while (*prefix != '\0') {
        if (*text++ != *prefix++) {
            return 0;
        }
    }
    return 1;
}

static void handle_command(const char *command, uint32_t now)
{
    if (text_equal(command, "REQUEST2") ||
        text_starts_with(command, "REQUEST2 ")) {
        if (approval_is_pending()) {
            uart_write("ERR BUSY\r\n");
        } else if (text_equal(command, "REQUEST2") ||
                   !approval_start(command + 9, now)) {
            uart_write("ERR INVALID_REQUEST\r\n");
        }
        return;
    }

    if (text_equal(command, "CANCEL")) {
        if (!approval_cancel()) {
            uart_write("ERR NO_PENDING_REQUEST\r\n");
        }
        return;
    }

    if (text_equal(command, "PING")) {
        uart_write("PONG\r\n");
    } else if (text_equal(command, "STATUS")) {
        uart_write(approval_is_pending() ? "WAITING_APPROVAL\r\n"
                                         : "READY\r\n");
    } else if (text_equal(command, "LED ON") ||
               text_equal(command, "LED OFF")) {
        /* The LED shows the pending state while a request is open. */
        if (approval_is_pending()) {
            uart_write("ERR BUSY\r\n");
        } else if (text_equal(command, "LED ON")) {
            led_set(1);
            uart_write("OK LED ON\r\n");
        } else {
            led_set(0);
            uart_write("OK LED OFF\r\n");
        }
    } else if (text_equal(command, "BUTTON")) {
        uart_write(button_pressed() ? "BUTTON PRESSED\r\n"
                                    : "BUTTON RELEASED\r\n");
    } else {
        uart_write("ERR UNKNOWN_COMMAND\r\n");
    }
}

void protocol_mark_overflow(void)
{
    error = LINE_RX_OVERFLOW;
}

void protocol_feed(uint8_t byte, uint32_t now)
{
    if (byte == '\r' || byte == '\n') {
        switch (error) {
        case LINE_TOO_LONG:
            uart_write("ERR COMMAND_TOO_LONG\r\n");
            break;
        case LINE_INVALID_CHARACTER:
            uart_write("ERR INVALID_CHARACTER\r\n");
            break;
        case LINE_RX_OVERFLOW:
            uart_write("ERR RX_OVERFLOW\r\n");
            break;
        case LINE_OK:
        default:
            if (length > 0u) {
                line[length] = '\0';
                handle_command(line, now);
            }
            break;
        }

        length = 0u;
        error = LINE_OK;
        return;
    }

    /* After an error, drop the rest of the line. */
    if (error != LINE_OK) {
        return;
    }

    if (byte < 32u || byte > 126u) {
        error = LINE_INVALID_CHARACTER;
        return;
    }

    if (length >= PROTOCOL_MAX_LINE) {
        error = LINE_TOO_LONG;
        return;
    }

    line[length++] = (char)byte;
}
