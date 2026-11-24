#ifndef SIGNER_CRYPTO_H
#define SIGNER_CRYPTO_H

#include <stdint.h>

#define SIGNER_REQUEST_ID_LENGTH 32u
#define SIGNER_DIGEST_LENGTH     64u
#define SIGNER_TARGET_MAX_LENGTH 32u
#define SIGNER_EXPIRY_MAX_LENGTH 16u
#define SIGNER_SIGNATURE_LENGTH  64u

/*
 * Canonical request fields (all null-terminated):
 *   request_id  32 lowercase hex characters (128-bit random ID)
 *   digest      64 lowercase hex characters (SHA-256 of the file)
 *   target      1..32 of [a-z0-9_-], must not start with '_' or '-'
 *   expires_at  Unix time, decimal, no leading zero, <= 2^53 - 1
 *
 * The firmware has no wall clock, so it validates the expiry format only;
 * the host enforces the actual validity period.
 */
int signer_validate_request(
    const char *request_id,
    const char *digest,
    const char *target,
    const char *expires_at
);

/* Signs, with the Ed25519 key derived from private_seed (32 bytes):
 *
 *   "SIGNER-LAB-V3 <request_id> <digest> <target> <expires_at> <counter>"
 *
 * counter is written in canonical decimal and must be 1..0xFFFFFFFE.
 * Returns 1 on success, 0 for invalid input (the signature output must
 * then not be used). */
int signer_sign_approval(
    uint8_t signature[SIGNER_SIGNATURE_LENGTH],
    const uint8_t private_seed[32],
    const char *request_id,
    const char *digest,
    const char *target,
    const char *expires_at,
    uint32_t counter
);

#endif
