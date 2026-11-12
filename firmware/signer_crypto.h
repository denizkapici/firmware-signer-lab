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

/* Returns 1 on success, 0 for invalid canonical V2 fields.
 * Inputs must be null-terminated strings.
 * On failure, the signature output must not be used.
 */
int signer_sign_approval_v2(
    uint8_t signature[64],
    const char *request_id,
    const char *digest,
    const char *target,
    const char *expires_at
);


int signer_validate_approval_v2(
    const char *request_id,
    const char *digest,
    const char *target,
    const char *expires_at
);

#endif
