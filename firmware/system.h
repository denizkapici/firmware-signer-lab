#ifndef SIGNER_SYSTEM_H
#define SIGNER_SYSTEM_H

#include <stdint.h>

extern volatile uint32_t system_milliseconds;

/* 1 ms SysTick on the 16 MHz core clock. */
void systick_init(void);

/* Independent watchdog, about 4 s timeout. Once started it cannot be
 * stopped; the main loop must call watchdog_kick() regularly. */
void watchdog_init(void);
void watchdog_kick(void);

/* Returns 1 if the last reset was caused by the watchdog, and clears the
 * reset flags. Call once at startup. */
int reset_was_watchdog(void);

#endif
