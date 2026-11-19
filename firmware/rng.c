#include "rng.h"

#include "board.h"

/* Iterations, not time: generous for a 16 MHz core and still bounded. */
#define PLL_READY_TIMEOUT 200000u
#define RNG_READY_TIMEOUT 200000u

static int ready;
static int failed;
static uint32_t previous;

static int read_word(uint32_t *word)
{
    uint32_t status = 0u;

    for (uint32_t i = 0u; i < RNG_READY_TIMEOUT; ++i) {
        status = RNG_SR;
        if ((status & (RNG_SR_SECS | RNG_SR_CECS |
                       RNG_SR_SEIS | RNG_SR_CEIS)) != 0u) {
            return 0;
        }
        if ((status & RNG_SR_DRDY) != 0u) {
            break;
        }
    }
    if ((status & RNG_SR_DRDY) == 0u) {
        return 0;
    }

    *word = RNG_DR;
    return 1;
}

int rng_init(void)
{
    if (ready) {
        return 1;
    }
    if (failed) {
        return 0;
    }

    /* PLL from HSI: VCO in = 16/8 = 2 MHz, VCO = 384 MHz,
     * PLLP = /4 (96 MHz, unused), PLLQ = /8 -> 48 MHz for the RNG. */
    if ((RCC_CR & RCC_CR_PLLON) == 0u) {
        RCC_PLLCFGR = 8u | (192u << 6) | (1u << 16) | (8u << 24);
        RCC_CR |= RCC_CR_PLLON;
    }

    uint32_t i = 0u;
    while ((RCC_CR & RCC_CR_PLLRDY) == 0u) {
        if (++i >= PLL_READY_TIMEOUT) {
            failed = 1;
            return 0;
        }
    }

    RCC_AHB2ENR |= RCC_AHB2ENR_RNGEN;
    (void)RCC_AHB2ENR;
    RNG_CR |= RNG_CR_RNGEN;

    /* The first word only seeds the continuous test. */
    if (!read_word(&previous)) {
        failed = 1;
        return 0;
    }

    ready = 1;
    return 1;
}

int rng_fill(uint8_t *output, uint32_t length)
{
    if (!ready) {
        return 0;
    }

    while (length != 0u) {
        uint32_t word;

        if (!read_word(&word) || word == previous) {
            ready = 0;
            failed = 1;
            return 0;
        }
        previous = word;

        for (uint32_t i = 0u; i < 4u && length != 0u; ++i) {
            *output++ = (uint8_t)(word >> (8u * i));
            --length;
        }
    }

    return 1;
}
