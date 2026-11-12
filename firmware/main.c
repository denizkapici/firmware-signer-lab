#include <stdint.h>
#include "signer_crypto.h"

#define REG32(address) (*(volatile uint32_t *)(address))

#define RCC_AHB1ENR  REG32(0x40023830u)
#define RCC_APB1ENR  REG32(0x40023840u)

#define GPIOC_MODER  REG32(0x40020800u)
#define GPIOC_AFRH   REG32(0x40020824u)

#define UART4_SR     REG32(0x40004C00u)
#define UART4_DR     REG32(0x40004C04u)
#define UART4_BRR    REG32(0x40004C08u)
#define UART4_CR1    REG32(0x40004C0Cu)

/* 16 MHz cekirdek saatinde 1 ms SysTick. */
#define SYST_CSR REG32(0xE000E010u)
#define SYST_RVR REG32(0xE000E014u)
#define SYST_CVR REG32(0xE000E018u)

volatile uint32_t system_milliseconds;

void SysTick_Handler(void)
{
    ++system_milliseconds;
}

static void systick_init(void)
{
    SYST_CSR = 0u;
    system_milliseconds = 0u;
    SYST_RVR = 16000u - 1u;
    SYST_CVR = 0u;

    /* ENABLE, TICKINT ve CLKSOURCE. */
    SYST_CSR = 7u;
}

static void uart_init(void)
{
    /* GPIOC ve UART4 saatlerini etkinlestir. */
    RCC_AHB1ENR |= (1u << 2);
    RCC_APB1ENR |= (1u << 19);

    /* Saat etkinlestirmesinden sonra register okuma. */
    (void)RCC_AHB1ENR;
    (void)RCC_APB1ENR;

    /* PC10 ve PC11: alternate function modu. */
    GPIOC_MODER &= ~((3u << 20) | (3u << 22));
    GPIOC_MODER |=  ((2u << 20) | (2u << 22));

    /* PC10 ve PC11: AF8, UART4. */
    GPIOC_AFRH &= ~((15u << 8) | (15u << 12));
    GPIOC_AFRH |=  ((8u << 8) | (8u << 12));

    UART4_CR1 = 0;

    /* Reset saat plani: 16 MHz PCLK1, yaklasik 115200 baud. */
    UART4_BRR = 0x008Bu;

    /* UART etkin, verici ve alici etkin. */
    UART4_CR1 = (1u << 13) | (1u << 3) | (1u << 2);
}

static void uart_write(const char *text)
{
    while (*text != '\0') {
        while ((UART4_SR & (1u << 7)) == 0u) {
        }

        UART4_DR = (uint8_t)*text++;
    }
}



#define GPIOA_MODER   REG32(0x40020000u)
#define GPIOA_PUPDR   REG32(0x4002000Cu)
#define GPIOA_IDR     REG32(0x40020010u)

#define GPIOD_MODER   REG32(0x40020C00u)
#define GPIOD_OTYPER  REG32(0x40020C04u)
#define GPIOD_PUPDR   REG32(0x40020C0Cu)
#define GPIOD_BSRR    REG32(0x40020C18u)

static void gpio_init(void)
{
    /* GPIOA ve GPIOD saatlerini etkinlestir. */
    RCC_AHB1ENR |= (1u << 0) | (1u << 3);
    (void)RCC_AHB1ENR;

    /* PA0: giris, pull-down; basili buton lojik 1. */
    GPIOA_MODER &= ~3u;
    GPIOA_PUPDR = (GPIOA_PUPDR & ~3u) | 2u;

    /* PD12: ilk cikis degeri 0, push-pull, pull yok. */
    GPIOD_BSRR = (1u << 28);
    GPIOD_OTYPER &= ~(1u << 12);
    GPIOD_PUPDR &= ~(3u << 24);
    GPIOD_MODER = (GPIOD_MODER & ~(3u << 24)) | (1u << 24);
}

static void led_set(int on)
{
    /* BSRR: alt 16 bit set, ust 16 bit reset. */
    GPIOD_BSRR = on ? (1u << 12) : (1u << 28);
}

static int button_pressed(void)
{
    return (GPIOA_IDR & 1u) != 0u;
}

static int text_equal(const char *left, const char *right)
{
    while (*left != '\0' && *left == *right) {
        ++left;
        ++right;
    }

    return *left == *right;
}


static int approval_pending;
static int approval_armed;
static int approval_last_raw;
static uint32_t approval_started;
static uint32_t approval_raw_since;
static char approval_id[33];
static int approval_version2;
static char approval_target[33];
static char approval_expiry[17];
static char approval_digest[65];

static int text_starts_with(const char *text, const char *prefix)
{
    while (*prefix != '\0') {
        if (*text++ != *prefix++) {
            return 0;
        }
    }
    return 1;
}

static int is_hex_character(char ch)
{
    return (ch >= '0' && ch <= '9') ||
           (ch >= 'a' && ch <= 'f') ||
           (ch >= 'A' && ch <= 'F');
}

static int request_valid(const char *command)
{
    uint32_t length = 0u;

    while (command[length] != '\0') {
        ++length;
    }

    /* REQUEST + bosluk + 8 hex kimlik + bosluk + 64 hex ozet. */
    if (length != 81u ||
        !text_starts_with(command, "REQUEST ") ||
        command[16] != ' ') {
        return 0;
    }

    for (uint32_t i = 8u; i < 16u; ++i) {
        if (!is_hex_character(command[i])) {
            return 0;
        }
    }

    for (uint32_t i = 17u; i < 81u; ++i) {
        if (!is_hex_character(command[i])) {
            return 0;
        }
    }

    return 1;
}

static void approval_response(const char *result)
{
    char encoded[129];
    int approved = text_equal(result, "APPROVED");

    if (approved) {
        static const char hex[] = "0123456789abcdef";
        uint8_t signature[64];

        if (approval_version2) {
            if (!signer_sign_approval_v2(
                    signature, approval_id, approval_digest,
                    approval_target, approval_expiry)) {
                uart_write("ERR SIGNING_FAILED\r\n");
                return;
            }
        } else {
            signer_sign_approval(signature, approval_id, approval_digest);
        }

        for (uint32_t i = 0u; i < 64u; ++i) {
            encoded[2u * i] = hex[signature[i] >> 4];
            encoded[2u * i + 1u] = hex[signature[i] & 15u];
        }
        encoded[128] = '\0';
    }

    uart_write(result);
    if (approval_version2) {
        uart_write("2");
    }
    uart_write(" ");
    uart_write(approval_id);
    uart_write(" ");
    uart_write(approval_digest);

    if (approval_version2) {
        uart_write(" ");
        uart_write(approval_target);
        uart_write(" ");
        uart_write(approval_expiry);
    }

    if (approved) {
        uart_write(" ");
        uart_write(encoded);
    }
    uart_write("\r\n");
}

static void approval_finish(const char *response)
{
    approval_pending = 0;
    approval_armed = 0;
    led_set(0);
    approval_response(response);
    approval_version2 = 0;
    for (uint32_t i = 0u; i < sizeof(approval_target); ++i) {
        approval_target[i] = '\0';
    }
    for (uint32_t i = 0u; i < sizeof(approval_expiry); ++i) {
        approval_expiry[i] = '\0';
    }

    for (uint32_t i = 0u; i < sizeof(approval_id); ++i) {
        approval_id[i] = '\0';
    }

    for (uint32_t i = 0u; i < sizeof(approval_digest); ++i) {
        approval_digest[i] = '\0';
    }
}

static void approval_start(const char *command)
{
    approval_version2 = 0;
    for (uint32_t i = 0u; i < 8u; ++i) {
        approval_id[i] = command[8u + i];
    }
    approval_id[8] = '\0';

    for (uint32_t i = 0u; i < 64u; ++i) {
        approval_digest[i] = command[17u + i];
    }
    approval_digest[64] = '\0';

    approval_started = system_milliseconds;
    approval_raw_since = approval_started;
    approval_last_raw = button_pressed();
    approval_armed = 0;
    approval_pending = 1;
    led_set(1);
    approval_response("PENDING");
}


static int read_v2_field(
    const char **cursor, char *output, uint32_t capacity, int last)
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

static int approval_start_v2(const char *command)
{
    char request_id[33];
    char digest[65];
    char target[33];
    char expiry[17];
    const char *cursor = command + 9u;

    if (!read_v2_field(&cursor, request_id, sizeof(request_id), 0) ||
        !read_v2_field(&cursor, digest, sizeof(digest), 0) ||
        !read_v2_field(&cursor, target, sizeof(target), 0) ||
        !read_v2_field(&cursor, expiry, sizeof(expiry), 1) ||
        !signer_validate_approval_v2(request_id, digest, target, expiry)) {
        return 0;
    }

    for (uint32_t i = 0u; i <= 32u; ++i) {
        approval_id[i] = request_id[i];
    }
    for (uint32_t i = 0u; i <= 64u; ++i) {
        approval_digest[i] = digest[i];
    }

    uint32_t i = 0u;
    do {
        approval_target[i] = target[i];
    } while (target[i++] != '\0');
    i = 0u;
    do {
        approval_expiry[i] = expiry[i];
    } while (expiry[i++] != '\0');

    approval_version2 = 1;
    approval_started = system_milliseconds;
    approval_raw_since = approval_started;
    approval_last_raw = button_pressed();
    approval_armed = 0;
    approval_pending = 1;
    led_set(1);
    approval_response("PENDING");
    return 1;
}

static void approval_poll(void)
{
    if (!approval_pending) {
        return;
    }

    uint32_t now = system_milliseconds;
    int raw = button_pressed();

    if ((uint32_t)(now - approval_started) >= 5000u) {
        approval_finish("TIMEOUT");
        return;
    }

    if (raw != approval_last_raw) {
        approval_last_raw = raw;
        approval_raw_since = now;
    }

    if ((uint32_t)(now - approval_raw_since) < 20u) {
        return;
    }

    if (!raw) {
        approval_armed = 1;
    } else if (approval_armed) {
        approval_finish("APPROVED");
    }
}

static void handle_command(const char *command)
{
    if (text_equal(command, "REQUEST2") ||
        text_starts_with(command, "REQUEST2 ")) {
        if (approval_pending) {
            uart_write("ERR BUSY\r\n");
        } else if (text_equal(command, "REQUEST2") ||
                   !approval_start_v2(command)) {
            uart_write("ERR INVALID_REQUEST\r\n");
        }
        return;
    }

    if (text_equal(command, "REQUEST") ||
        text_starts_with(command, "REQUEST ")) {
        if (approval_pending) {
            uart_write("ERR BUSY\r\n");
        } else if (!request_valid(command)) {
            uart_write("ERR INVALID_REQUEST\r\n");
        } else {
            approval_start(command);
        }
        return;
    }

    if (text_equal(command, "CANCEL")) {
        if (approval_pending) {
            approval_finish("CANCELLED");
        } else {
            uart_write("ERR NO_PENDING_REQUEST\r\n");
        }
        return;
    }

    if (approval_pending && text_equal(command, "STATUS")) {
        uart_write("WAITING_APPROVAL\r\n");
        return;
    }

    if (approval_pending &&
        (text_equal(command, "LED ON") ||
         text_equal(command, "LED OFF"))) {
        uart_write("ERR BUSY\r\n");
        return;
    }

    if (text_equal(command, "PING")) {
        uart_write("PONG\r\n");
    } else if (text_equal(command, "STATUS")) {
        uart_write("READY\r\n");
    } else if (text_equal(command, "LED ON")) {
        led_set(1);
        uart_write("OK LED ON\r\n");
    } else if (text_equal(command, "LED OFF")) {
        led_set(0);
        uart_write("OK LED OFF\r\n");
    } else if (text_equal(command, "BUTTON")) {
        uart_write(button_pressed()
            ? "BUTTON PRESSED\r\n"
            : "BUTTON RELEASED\r\n");
    } else {
        uart_write("ERR UNKNOWN_COMMAND\r\n");
    }
}

int main(void)
{
    char command[256];
    uint32_t length = 0;
    int too_long = 0;
    int invalid_character = 0;

    gpio_init();
    uart_init();
    systick_init();
    uart_write("Signer firmware started\r\n");

    for (;;) {
        approval_poll();

        if ((UART4_SR & (1u << 5)) == 0u) {
            /* SysTick her milisaniyede islemciyi uyandirir. */
            __asm volatile ("wfi");
            continue;
        }

        unsigned char ch = (unsigned char)(UART4_DR & 0xFFu);

        /* CR, LF ve CRLF satir sonlarini destekle. */
        if (ch == '\r' || ch == '\n') {
            if (too_long) {
                uart_write("ERR COMMAND_TOO_LONG\r\n");
            } else if (invalid_character) {
                uart_write("ERR INVALID_CHARACTER\r\n");
            } else if (length > 0u) {
                command[length] = '\0';
                handle_command(command);
            }

            length = 0;
            too_long = 0;
            invalid_character = 0;
            continue;
        }

        /* Hatali satirin kalanini satir sonuna kadar at. */
        if (too_long || invalid_character) {
            continue;
        }

        /* Ilk protokol yalnizca yazdirilabilir ASCII kabul eder. */
        if (ch < 32u || ch > 126u) {
            invalid_character = 1;
            continue;
        }

        /* Sonlandirici '\0' icin bir bayt ayir. */
        /* Only REQUEST2 may exceed the V1 limit of 127 characters. */
        if (length >= sizeof(command) - 1u ||
            (length >= 127u &&
             !text_starts_with(command, "REQUEST2 "))) {
            too_long = 1;
            continue;
        }

        command[length++] = (char)ch;
    }
}
