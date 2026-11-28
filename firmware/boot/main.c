/*
 * Secure bootloader: verifies the application in slot A and starts it
 * only if its Ed25519 signature is valid for the firmware signing key
 * compiled into this image. Otherwise it reports why and halts.
 *
 * Deliberately minimal: no interrupts, no watchdog, polled UART output.
 */

#include <stdint.h>

#include "board.h"
#include "firmware_public_key.h"
#include "image.h"

#define SCB_VTOR REG32(0xE000ED08u)
#define USART_SR_TC (1u << 6)

static void uart_init_polled(void)
{
    RCC_AHB1ENR |= RCC_AHB1ENR_GPIOCEN;
    RCC_APB1ENR |= RCC_APB1ENR_UART4EN;
    (void)RCC_AHB1ENR;
    (void)RCC_APB1ENR;

    GPIOC_MODER &= ~((3u << 20) | (3u << 22));
    GPIOC_MODER |=  ((2u << 20) | (2u << 22));
    GPIOC_AFRH &= ~((15u << 8) | (15u << 12));
    GPIOC_AFRH |=  ((8u << 8) | (8u << 12));

    UART4_CR1 = 0u;
    UART4_BRR = 0x008Bu;  /* 115200 baud at 16 MHz */
    UART4_CR1 = USART_CR1_UE | USART_CR1_TE;
}

static void put(const char *text)
{
    while (*text != '\0') {
        while ((UART4_SR & USART_SR_TXE) == 0u) {
        }
        UART4_DR = (uint8_t)*text++;
    }
}

static void put_u32(uint32_t value)
{
    char text[11];
    uint32_t position = sizeof(text) - 1u;

    text[position] = '\0';
    do {
        text[--position] = (char)('0' + value % 10u);
        value /= 10u;
    } while (value != 0u);
    put(&text[position]);
}

static void led_init(void)
{
    RCC_AHB1ENR |= RCC_AHB1ENR_GPIODEN;
    (void)RCC_AHB1ENR;
    GPIOD_BSRR = 1u << 28;
    GPIOD_MODER = (GPIOD_MODER & ~(3u << 24)) | (1u << 24);
}

__attribute__((noreturn))
static void halt(void)
{
    put("BOOT HALT\r\n");
    led_init();
    for (;;) {
        GPIOD_BSRR = 1u << 12;
        for (volatile uint32_t i = 0u; i < 1600000u; ++i) {
        }
        GPIOD_BSRR = 1u << 28;
        for (volatile uint32_t i = 0u; i < 1600000u; ++i) {
        }
    }
}

__attribute__((noreturn))
static void start_application(const struct image_info *info, uint32_t vectors)
{
    /* Let the last character leave the shift register: the application
     * reconfigures the UART first thing. */
    while ((UART4_SR & USART_SR_TC) == 0u) {
    }

    SCB_VTOR = vectors;
    __asm volatile ("dsb\n\tisb" ::: "memory");
    __asm volatile (
        "msr msp, %0\n\t"
        "bx %1\n\t"
        :: "r"(info->stack_pointer), "r"(info->entry) : "memory");
    __builtin_unreachable();
}

int main(void)
{
    struct image_info info;

    uart_init_polled();
    put("BOOT signer-lab bootloader\r\n");

    enum image_status status = image_verify(
        (const uint8_t *)SLOT_A_ADDRESS, SLOT_A_ADDRESS, SLOT_A_SIZE,
        firmware_public_key, &info);

    put("BOOT SLOT A ");
    put(image_status_name(status));
    if (status != IMAGE_OK) {
        put("\r\n");
        halt();
    }

    put(" version=");
    put_u32(info.version);
    put("\r\n");

    start_application(&info, SLOT_A_ADDRESS + IMAGE_HEADER_SIZE);
}
