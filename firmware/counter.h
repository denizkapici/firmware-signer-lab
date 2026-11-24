#ifndef SIGNER_COUNTER_H
#define SIGNER_COUNTER_H

#include <stdint.h>

/*
 * Monotonic approval counter kept in flash (see docs/key-management.md).
 *
 * Every signature uses a new, strictly larger value, and the value is
 * stored *before* the signature is produced, so a reset can skip numbers
 * but can never make the device reuse one.
 *
 * Storage: an append-only log of (value, ~value) word pairs in two flash
 * sectors. When the active sector is full, the other one is erased and
 * the log continues there. The current value is the largest valid entry
 * found in either sector.
 */

#define COUNTER_MAX 0xFFFFFFFEu

/* Scans both sectors. Returns 1 on success. */
int counter_init(void);

/* Last value used (0 = no signature made yet). */
uint32_t counter_value(void);

/* Persists value + 1 and returns it in *next. Returns 0 if the flash
 * write failed or the counter is exhausted; the value is then not used. */
int counter_next(uint32_t *next);

#endif
