#include <stdint.h>

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

static void approval_finish(const char *response)
{
    approval_pending = 0;
    approval_armed = 0;
    led_set(0);
    uart_write(response);
}

static void approval_start(void)
{
    approval_started = system_milliseconds;
    approval_raw_since = approval_started;
    approval_last_raw = button_pressed();
    approval_armed = 0;
    approval_pending = 1;
    led_set(1);
    uart_write("PENDING\r\n");
}

static void approval_poll(void)
{
    if (!approval_pending) {
        return;
    }

    uint32_t now = system_milliseconds;
    int raw = button_pressed();

    if ((uint32_t)(now - approval_started) >= 5000u) {
        approval_finish("TIMEOUT\r\n");
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
        approval_finish("APPROVED\r\n");
    }
}

static void handle_command(const char *command)
{
    if (text_equal(command, "REQUEST")) {
        if (approval_pending) {
            uart_write("ERR BUSY\r\n");
        } else {
            approval_start();
        }
        return;
    }

    if (text_equal(command, "CANCEL")) {
        if (approval_pending) {
            approval_finish("CANCELLED\r\n");
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
    char command[64];
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
        if (length >= sizeof(command) - 1u) {
            too_long = 1;
            continue;
        }

        command[length++] = (char)ch;
    }
}
