#include "gpio.h"

#include "board.h"

void gpio_init(void)
{
    RCC_AHB1ENR |= RCC_AHB1ENR_GPIOAEN | RCC_AHB1ENR_GPIODEN;
    (void)RCC_AHB1ENR;

    /* PA0: input with pull-down. */
    GPIOA_MODER &= ~3u;
    GPIOA_PUPDR = (GPIOA_PUPDR & ~3u) | 2u;

    /* PD12: drive low first, then switch to push-pull output. */
    GPIOD_BSRR = 1u << 28;
    GPIOD_OTYPER &= ~(1u << 12);
    GPIOD_PUPDR &= ~(3u << 24);
    GPIOD_MODER = (GPIOD_MODER & ~(3u << 24)) | (1u << 24);
}

void led_set(int on)
{
    /* BSRR: low half sets, high half resets. */
    GPIOD_BSRR = on ? (1u << 12) : (1u << 28);
}

int button_pressed(void)
{
    return (GPIOA_IDR & 1u) != 0u;
}
