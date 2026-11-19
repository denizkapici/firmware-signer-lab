#ifndef SIGNER_RNG_H
#define SIGNER_RNG_H

#include <stdint.h>

/* Hardware true random number generator (STM32F4 RNG).
 *
 * The RNG needs the 48 MHz PLL48CLK, so rng_init() starts the PLL from
 * the 16 MHz HSI (M=8, N=192, Q=8). The CPU keeps running on HSI.
 *
 * Every word is checked: seed and clock error flags, and the continuous
 * test from FIPS 140-2 (two consecutive equal words are rejected). Any
 * error is permanent until reset. Returns 1 on success, 0 on failure. */
int rng_init(void);
int rng_fill(uint8_t *output, uint32_t length);

#endif
