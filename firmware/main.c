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

int main(void)
{
    uart_init();
    uart_write("Signer firmware started\r\n");

    for (;;) {
        __asm volatile ("wfi");
    }
}
