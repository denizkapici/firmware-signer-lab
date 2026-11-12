#ifndef SIGNER_CRYPTO_H
#define SIGNER_CRYPTO_H

#include <stdint.h>

/* Inputs: validated 8-character ID and 64-character digest.
 * Output: 64-byte Ed25519 signature.
 */
void signer_sign_approval(
    uint8_t signature[64],
    const char request_id[9],
    const char digest[65]
);

#endif
