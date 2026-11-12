#include <stdint.h>
#include <stddef.h>
#include "monocypher.h"
#include "monocypher-ed25519.h"

/* Public RFC 8032 TEST 1 key: test use only. */
volatile uint32_t crypto_test_result;

void SysTick_Handler(void)
{
    /* SysTick is not enabled in this test firmware. */
}

static unsigned digit(char ch)
{
    return ch <= '9' ? (unsigned)(ch - '0')
                     : (unsigned)(ch - 'a' + 10);
}

static void decode(uint8_t *out, size_t size, const char *hex)
{
    for (size_t i = 0; i < size; ++i) {
        out[i] = (uint8_t)(
            (digit(hex[2u * i]) << 4) | digit(hex[2u * i + 1u])
        );
    }
}

static int equal(const uint8_t *a, const uint8_t *b, size_t size)
{
    for (size_t i = 0; i < size; ++i) {
        if (a[i] != b[i]) {
            return 0;
        }
    }
    return 1;
}

int main(void)
{
    uint8_t seed[32];
    uint8_t secret_key[64];
    uint8_t public_key[32];
    uint8_t expected_public_key[32];
    uint8_t signature[64];
    uint8_t expected_signature[64];
    const uint8_t message[1] = {0};
    const uint8_t changed_message[1] = {1};

    decode(seed, sizeof(seed),
        "9d61b19deffd5a60ba844af492ec2cc4"
        "4449c5697b326919703bac031cae7f60");
    decode(expected_public_key, sizeof(expected_public_key),
        "d75a980182b10ab7d54bfed3c964073a"
        "0ee172f3daa62325af021a68f707511a");
    decode(expected_signature, sizeof(expected_signature),
        "e5564300c360ac729086e2cc806e828a"
        "84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46b"
        "d25bf5f0595bbe24655141438e7a100b");

    crypto_ed25519_key_pair(secret_key, public_key, seed);
    if (!equal(public_key, expected_public_key, 32)) {
        goto cleanup;
    }
    crypto_test_result |= 1u;

    crypto_ed25519_sign(signature, secret_key, message, 0);
    if (!equal(signature, expected_signature, 64)) {
        goto cleanup;
    }
    crypto_test_result |= 2u;

    if (crypto_ed25519_check(signature, public_key, message, 0) != 0) {
        goto cleanup;
    }
    crypto_test_result |= 4u;

    if (crypto_ed25519_check(
            signature, public_key, changed_message, 1) == 0) {
        goto cleanup;
    }
    crypto_test_result |= 8u;

    signature[0] ^= 1u;
    if (crypto_ed25519_check(signature, public_key, message, 0) == 0) {
        goto cleanup;
    }
    crypto_test_result |= 16u;

cleanup:
    crypto_wipe(secret_key, sizeof(secret_key));
    return 0;
}
