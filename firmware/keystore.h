#ifndef SIGNER_KEYSTORE_H
#define SIGNER_KEYSTORE_H

#include <stdint.h>

/*
 * Device signing key, kept in flash sector 3 (see docs/key-management.md).
 *
 *   EMPTY      sector erased: a key is generated on first boot
 *   READY      record valid: the stored public key matches the one
 *              derived from the stored seed
 *   CORRUPT    record present but inconsistent: signing is refused and
 *              the key is NOT replaced automatically
 *   FAILED     generation failed (RNG or flash error): signing refused
 */
enum keystore_state {
    KEYSTORE_EMPTY = 0,
    KEYSTORE_READY,
    KEYSTORE_CORRUPT,
    KEYSTORE_FAILED
};

/* Loads the key, or generates and stores one if the sector is erased.
 * Prints INFO/WARN lines describing the outcome. */
enum keystore_state keystore_init(void);

int keystore_ready(void);

/* Valid only when keystore_ready(). Points into flash. */
const uint8_t *keystore_seed(void);
const uint8_t *keystore_public_key(void);

#endif
