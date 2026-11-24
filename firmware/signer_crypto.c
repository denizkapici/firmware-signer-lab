#include <stddef.h>
#include <stdint.h>
#include "signer_crypto.h"
#include "monocypher.h"
#include "monocypher-ed25519.h"

static int lower_hex(const char *text, size_t length)
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

int signer_validate_request(
    const char *request_id,
    const char *digest,
    const char *target,
    const char *expires_at)
{
    if (request_id == NULL || digest == NULL ||
        target == NULL || expires_at == NULL) {
        return 0;
    }

    if (!lower_hex(request_id, 32u) ||
        !lower_hex(digest, 64u)) {
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

    return 1;
}

int signer_sign_approval(
    uint8_t signature[64],
    const uint8_t private_seed[32],
    const char *request_id,
    const char *digest,
    const char *target,
    const char *expires_at,
    uint32_t counter)
{
    if (signature == NULL || private_seed == NULL ||
        counter == 0u || counter == UINT32_MAX ||
        !signer_validate_request(request_id, digest, target, expires_at)) {
        return 0;
    }

    size_t target_length = 0u;
    size_t expiry_length = 0u;
    while (target[target_length] != '\0') {
        ++target_length;
    }
    while (expires_at[expiry_length] != '\0') {
        ++expiry_length;
    }

    static const char prefix[] = "SIGNER-LAB-V3 ";
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

    /* Counter: canonical decimal, no leading zero. */
    char digits[10];
    size_t digit_count = 0u;
    for (uint32_t rest = counter; rest != 0u; rest /= 10u) {
        digits[digit_count++] = (char)('0' + rest % 10u);
    }
    message[position++] = (uint8_t)' ';
    while (digit_count != 0u) {
        message[position++] = (uint8_t)digits[--digit_count];
    }

    uint8_t seed[32];
    uint8_t secret_key[64];
    uint8_t public_key[32];

    for (size_t i = 0u; i < sizeof(seed); ++i) {
        seed[i] = private_seed[i];
    }

    /* key_pair wipes the seed copy. */
    crypto_ed25519_key_pair(secret_key, public_key, seed);
    crypto_ed25519_sign(signature, secret_key, message, position);
    crypto_wipe(secret_key, sizeof(secret_key));
    crypto_wipe(message, sizeof(message));
    return 1;
}
