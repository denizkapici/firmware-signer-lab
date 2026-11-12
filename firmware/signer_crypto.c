#include <stddef.h>
#include <stdint.h>
#include "signer_crypto.h"
#include "monocypher.h"
#include "monocypher-ed25519.h"

#if !defined(SIGNER_DEMO_KEY) || SIGNER_DEMO_KEY != 1
#error "Demo signing requires SIGNER_DEMO_KEY=1."
#endif

/* RFC 8032 TEST 1: PUBLIC TEST KEY, NOT A PRODUCTION SECRET. */
static const uint8_t demo_seed[32] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60
};

void signer_sign_approval(
    uint8_t signature[64],
    const char request_id[9],
    const char digest[65])
{
    static const char prefix[] = "SIGNER-LAB-V1 ";
    uint8_t message[(sizeof(prefix) - 1u) + 8u + 1u + 64u];
    uint8_t seed[32];
    uint8_t secret_key[64];
    uint8_t public_key[32];
    size_t position = 0u;

    for (size_t i = 0u; i < sizeof(prefix) - 1u; ++i) {
        message[position++] = (uint8_t)prefix[i];
    }

    for (size_t i = 0u; i < 8u; ++i) {
        message[position++] = (uint8_t)request_id[i];
    }

    message[position++] = (uint8_t)' ';

    for (size_t i = 0u; i < 64u; ++i) {
        message[position++] = (uint8_t)digest[i];
    }

    for (size_t i = 0u; i < sizeof(seed); ++i) {
        seed[i] = demo_seed[i];
    }

    crypto_ed25519_key_pair(secret_key, public_key, seed);
    crypto_ed25519_sign(signature, secret_key, message, position);

    crypto_wipe(secret_key, sizeof(secret_key));
    crypto_wipe(seed, sizeof(seed));
}


static int v2_lower_hex(const char *text, size_t length)
{
    for (size_t i = 0u; i < length; ++i) {
        char ch = text[i];
        if (!((ch >= '0' && ch <= '9') ||
              (ch >= 'a' && ch <= 'f'))) {
            return 0;
        }
    }
    return text[length] == '\0';
}

int signer_sign_approval_v2(
    uint8_t signature[64],
    const char *request_id,
    const char *digest,
    const char *target,
    const char *expires_at)
{
    if (signature == NULL || request_id == NULL || digest == NULL ||
        target == NULL || expires_at == NULL) {
        return 0;
    }

    if (!v2_lower_hex(request_id, 32u) ||
        !v2_lower_hex(digest, 64u)) {
        return 0;
    }

    size_t target_length = 0u;
    while (target[target_length] != '\0') {
        if (target_length >= 32u) {
            return 0;
        }
        char ch = target[target_length];
        int alphanumeric = (ch >= 'a' && ch <= 'z') ||
                           (ch >= '0' && ch <= '9');
        if (!alphanumeric &&
            !(target_length > 0u && (ch == '_' || ch == '-'))) {
            return 0;
        }
        ++target_length;
    }
    if (target_length == 0u) {
        return 0;
    }

    /* Canonical positive decimal, no leading zeros. */
    if (expires_at[0] < '1' || expires_at[0] > '9') {
        return 0;
    }
    size_t expiry_length = 0u;
    uint64_t expiry = 0u;
    while (expires_at[expiry_length] != '\0') {
        if (expiry_length >= 16u) {
            return 0;
        }
        char ch = expires_at[expiry_length];
        if (ch < '0' || ch > '9') {
            return 0;
        }
        expiry = expiry * 10u + (uint64_t)(ch - '0');
        ++expiry_length;
    }
    if (expiry > UINT64_C(9007199254740991)) {
        return 0;
    }

    static const char prefix[] = "SIGNER-LAB-V2 ";
    uint8_t message[192];
    size_t position = 0u;

    for (size_t i = 0u; i < sizeof(prefix) - 1u; ++i) {
        message[position++] = (uint8_t)prefix[i];
    }

    const char *fields[] = {request_id, digest, target, expires_at};
    const size_t lengths[] = {32u, 64u, target_length, expiry_length};

    for (size_t field = 0u; field < 4u; ++field) {
        if (field != 0u) {
            message[position++] = (uint8_t)' ';
        }
        for (size_t i = 0u; i < lengths[field]; ++i) {
            message[position++] = (uint8_t)fields[field][i];
        }
    }

    uint8_t seed[32];
    uint8_t secret_key[64];
    uint8_t public_key[32];

    for (size_t i = 0u; i < sizeof(seed); ++i) {
        seed[i] = demo_seed[i];
    }

    crypto_ed25519_key_pair(secret_key, public_key, seed);
    crypto_ed25519_sign(signature, secret_key, message, position);
    crypto_wipe(secret_key, sizeof(secret_key));
    crypto_wipe(seed, sizeof(seed));
    return 1;
}
