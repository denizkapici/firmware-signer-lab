#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "monocypher.h"
#include "monocypher-ed25519.h"

/* Public test material from RFC 8032, section 7.1, TEST 1.
 * Never use this key for real signing.
 */

static unsigned hex_digit(char ch)
{
    if (ch >= '0' && ch <= '9') {
        return (unsigned)(ch - '0');
    }
    if (ch >= 'a' && ch <= 'f') {
        return (unsigned)(ch - 'a' + 10);
    }
    fprintf(stderr, "Invalid test vector hex\n");
    exit(1);
}

static void decode_hex(uint8_t *out, size_t size, const char *hex)
{
    if (strlen(hex) != size * 2u) {
        fprintf(stderr, "Invalid test vector length\n");
        exit(1);
    }

    for (size_t i = 0; i < size; ++i) {
        out[i] = (uint8_t)(
            (hex_digit(hex[2u * i]) << 4) |
            hex_digit(hex[2u * i + 1u])
        );
    }
}

static void require(int condition, const char *name)
{
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", name);
        exit(1);
    }
    printf("PASS: %s\n", name);
}

int main(void)
{
    uint8_t seed[32];
    uint8_t secret_key[64];
    uint8_t public_key[32];
    uint8_t expected_public_key[32];
    uint8_t signature[64];
    uint8_t expected_signature[64];
    const uint8_t empty_message[1] = {0};
    const uint8_t changed_message[1] = {1};

    decode_hex(seed, sizeof(seed),
        "9d61b19deffd5a60ba844af492ec2cc4"
        "4449c5697b326919703bac031cae7f60");

    decode_hex(expected_public_key, sizeof(expected_public_key),
        "d75a980182b10ab7d54bfed3c964073a"
        "0ee172f3daa62325af021a68f707511a");

    decode_hex(expected_signature, sizeof(expected_signature),
        "e5564300c360ac729086e2cc806e828a"
        "84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46b"
        "d25bf5f0595bbe24655141438e7a100b");

    crypto_ed25519_key_pair(secret_key, public_key, seed);

    require(
        memcmp(public_key, expected_public_key, sizeof(public_key)) == 0,
        "RFC 8032 public key"
    );

    crypto_ed25519_sign(
        signature, secret_key, empty_message, 0
    );

    require(
        memcmp(signature, expected_signature, sizeof(signature)) == 0,
        "RFC 8032 signature"
    );

    require(
        crypto_ed25519_check(
            signature, public_key, empty_message, 0
        ) == 0,
        "Valid signature accepted"
    );

    require(
        crypto_ed25519_check(
            signature, public_key, changed_message,
            sizeof(changed_message)
        ) != 0,
        "Changed message rejected"
    );

    signature[0] ^= 1u;

    require(
        crypto_ed25519_check(
            signature, public_key, empty_message, 0
        ) != 0,
        "Corrupted signature rejected"
    );

    crypto_wipe(secret_key, sizeof(secret_key));
    puts("All Ed25519 checks passed.");
    return 0;
}
