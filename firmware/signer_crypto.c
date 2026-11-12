#include <stddef.h>
#include <stdint.h>
#include "signer_crypto.h"
#include "monocypher.h"
#include "monocypher-ed25519.h"

#ifndef SIGNER_DEMO_KEY
#error "Only the explicit demo-key build is currently supported."
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
