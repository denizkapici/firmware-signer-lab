#include "approval.h"

#include "gpio.h"
#include "signer_crypto.h"
#include "system.h"
#include "uart.h"

struct pending_request {
    char request_id[SIGNER_REQUEST_ID_LENGTH + 1u];
    char digest[SIGNER_DIGEST_LENGTH + 1u];
    char target[SIGNER_TARGET_MAX_LENGTH + 1u];
    char expires_at[SIGNER_EXPIRY_MAX_LENGTH + 1u];
};

static struct pending_request request;
static int pending;
static int armed;
static int last_raw;
static uint32_t started_at;
static uint32_t raw_since;

static void wipe(void *data, uint32_t size)
{
    volatile uint8_t *bytes = data;
    while (size-- != 0u) {
        *bytes++ = 0u;
    }
}

/* Copies one space-separated field. Returns 0 if it is empty or longer
 * than capacity - 1 characters. */
static int read_field(const char **cursor, char *output, uint32_t capacity,
                      int last)
{
    uint32_t length = 0u;

    while (**cursor != '\0' && **cursor != ' ') {
        if (length >= capacity - 1u) {
            return 0;
        }
        output[length++] = *(*cursor)++;
    }
    output[length] = '\0';

    if (length == 0u) {
        return 0;
    }
    if (last) {
        return **cursor == '\0';
    }
    if (**cursor != ' ') {
        return 0;
    }
    ++(*cursor);
    return 1;
}

static void write_fields(void)
{
    uart_write(request.request_id);
    uart_write(" ");
    uart_write(request.digest);
    uart_write(" ");
    uart_write(request.target);
    uart_write(" ");
    uart_write(request.expires_at);
}

static void finish(const char *status)
{
    pending = 0;
    armed = 0;
    led_set(0);

    uart_write(status);
    uart_write(" ");
    write_fields();
    uart_write("\r\n");

    wipe(&request, sizeof(request));
}

static void approve(void)
{
    static const char hex[] = "0123456789abcdef";
    uint8_t signature[SIGNER_SIGNATURE_LENGTH];
    char encoded[2u * SIGNER_SIGNATURE_LENGTH + 1u];

    /* Signing takes a noticeable time on a 16 MHz core. */
    watchdog_kick();

    if (!signer_sign_approval_v2(signature, request.request_id,
                                 request.digest, request.target,
                                 request.expires_at)) {
        /* Fields were validated on entry, so this indicates a bug. */
        uart_write("ERR SIGNING_FAILED\r\n");
        pending = 0;
        armed = 0;
        led_set(0);
        wipe(&request, sizeof(request));
        return;
    }

    for (uint32_t i = 0u; i < SIGNER_SIGNATURE_LENGTH; ++i) {
        encoded[2u * i] = hex[signature[i] >> 4];
        encoded[2u * i + 1u] = hex[signature[i] & 15u];
    }
    encoded[2u * SIGNER_SIGNATURE_LENGTH] = '\0';

    pending = 0;
    armed = 0;
    led_set(0);

    uart_write("APPROVED2 ");
    write_fields();
    uart_write(" ");
    uart_write(encoded);
    uart_write("\r\n");

    wipe(&request, sizeof(request));
    wipe(signature, sizeof(signature));
}

int approval_is_pending(void)
{
    return pending;
}

int approval_start(const char *fields, uint32_t now)
{
    struct pending_request parsed;
    const char *cursor = fields;

    if (pending) {
        return 0;
    }

    if (!read_field(&cursor, parsed.request_id,
                    sizeof(parsed.request_id), 0) ||
        !read_field(&cursor, parsed.digest, sizeof(parsed.digest), 0) ||
        !read_field(&cursor, parsed.target, sizeof(parsed.target), 0) ||
        !read_field(&cursor, parsed.expires_at,
                    sizeof(parsed.expires_at), 1) ||
        !signer_validate_approval_v2(parsed.request_id, parsed.digest,
                                     parsed.target, parsed.expires_at)) {
        return 0;
    }

    request = parsed;
    started_at = now;
    raw_since = now;
    last_raw = button_pressed();
    armed = 0;
    pending = 1;
    led_set(1);

    uart_write("PENDING2 ");
    write_fields();
    uart_write("\r\n");
    return 1;
}

int approval_cancel(void)
{
    if (!pending) {
        return 0;
    }

    finish("CANCELLED2");
    return 1;
}

void approval_poll(uint32_t now)
{
    if (!pending) {
        return;
    }

    if ((uint32_t)(now - started_at) >= APPROVAL_TIMEOUT_MS) {
        finish("TIMEOUT2");
        return;
    }

    int raw = button_pressed();
    if (raw != last_raw) {
        last_raw = raw;
        raw_since = now;
    }

    if ((uint32_t)(now - raw_since) < APPROVAL_DEBOUNCE_MS) {
        return;
    }

    if (!raw) {
        armed = 1;
    } else if (armed) {
        approve();
    }
}
