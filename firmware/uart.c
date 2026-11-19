#include "uart.h"

#include "board.h"

/* Power of two so the index wrap is a mask. Must hold at least one full
 * command line plus whatever arrives while a signature is computed. */
#define RX_BUFFER_SIZE 512u
#define RX_BUFFER_MASK (RX_BUFFER_SIZE - 1u)

/* Single producer (ISR) and single consumer (main loop): head is written
 * only by the ISR, tail only by the main loop, so no lock is needed. */
static volatile uint8_t rx_buffer[RX_BUFFER_SIZE];
static volatile uint32_t rx_head;
static volatile uint32_t rx_tail;
static volatile uint32_t rx_overflow;

void UART4_IRQHandler(void)
{
    uint32_t status = UART4_SR;

    if ((status & (USART_SR_RXNE | USART_SR_ORE)) == 0u) {
        return;
    }

    /* Reading DR clears RXNE, and (after the SR read above) also ORE. */
    uint8_t byte = (uint8_t)(UART4_DR & 0xFFu);

    if ((status & USART_SR_ORE) != 0u) {
        rx_overflow = 1u;
    }

    uint32_t head = rx_head;
    uint32_t next = (head + 1u) & RX_BUFFER_MASK;

    if (next == rx_tail) {
        rx_overflow = 1u;
        return;
    }

    rx_buffer[head] = byte;
    rx_head = next;
}

void uart_init(void)
{
    RCC_AHB1ENR |= RCC_AHB1ENR_GPIOCEN;
    RCC_APB1ENR |= RCC_APB1ENR_UART4EN;
    /* Read back so the clock is running before the peripheral is touched. */
    (void)RCC_AHB1ENR;
    (void)RCC_APB1ENR;

    /* PC10, PC11: alternate function 8 (UART4). */
    GPIOC_MODER &= ~((3u << 20) | (3u << 22));
    GPIOC_MODER |=  ((2u << 20) | (2u << 22));
    GPIOC_AFRH &= ~((15u << 8) | (15u << 12));
    GPIOC_AFRH |=  ((8u << 8) | (8u << 12));

    rx_head = 0u;
    rx_tail = 0u;
    rx_overflow = 0u;

    UART4_CR1 = 0u;
    /* 16 MHz / 115200 = 138.9 -> 0x8B (0.08 % error). */
    UART4_BRR = 0x008Bu;
    UART4_CR1 = USART_CR1_UE | USART_CR1_TE | USART_CR1_RE | USART_CR1_RXNEIE;

    NVIC_ISER(UART4_IRQn / 32u) = 1u << (UART4_IRQn % 32u);
}

int uart_read_byte(uint8_t *byte)
{
    uint32_t tail = rx_tail;

    if (tail == rx_head) {
        return 0;
    }

    *byte = rx_buffer[tail];
    rx_tail = (tail + 1u) & RX_BUFFER_MASK;
    return 1;
}

int uart_take_overflow(void)
{
    if (rx_overflow == 0u) {
        return 0;
    }

    rx_overflow = 0u;
    return 1;
}

void uart_write_polled(const char *text)
{
    while (*text != '\0') {
        while ((UART4_SR & USART_SR_TXE) == 0u) {
        }
        UART4_DR = (uint8_t)*text++;
    }
}

void uart_write(const char *text)
{
    uart_write_polled(text);
}

void uart_write_hex32_polled(uint32_t value)
{
    static const char hex[] = "0123456789abcdef";
    char text[9];

    for (uint32_t i = 0u; i < 8u; ++i) {
        text[i] = hex[(value >> (28u - 4u * i)) & 15u];
    }
    text[8] = '\0';
    uart_write_polled(text);
}
