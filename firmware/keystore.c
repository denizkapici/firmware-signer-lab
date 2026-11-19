#include "keystore.h"

#include "board.h"
#include "flash.h"
#include "monocypher-ed25519.h"
#include "rng.h"
#include "system.h"
#include "uart.h"

#define KEYSTORE_MAGIC   0x59454B53u   /* "SKEY" little endian */
#define KEYSTORE_VERSION 1u
#define ERASED_WORD      0xFFFFFFFFu

/* Written once; the magic word goes last so a record interrupted by a
 * reset is never mistaken for a complete one. */
struct key_record {
    uint32_t magic;
    uint32_t version;
    uint8_t seed[32];
    uint8_t public_key[32];
};

#define RECORD_WORDS (sizeof(struct key_record) / 4u)

static const struct key_record *const stored =
    (const struct key_record *)KEYSTORE_ADDRESS;

static enum keystore_state state = KEYSTORE_EMPTY;

static void wipe(void *data, uint32_t size)
{
    volatile uint8_t *bytes = data;
    while (size-- != 0u) {
        *bytes++ = 0u;
    }
}

static int bytes_equal(const uint8_t *left, const uint8_t *right, uint32_t size)
{
    uint8_t difference = 0u;
    for (uint32_t i = 0u; i < size; ++i) {
        difference |= (uint8_t)(left[i] ^ right[i]);
    }
    return difference == 0u;
}

static void derive_public_key(uint8_t public_key[32], const uint8_t seed[32])
{
    uint8_t secret[64];
    uint8_t seed_copy[32];

    for (uint32_t i = 0u; i < 32u; ++i) {
        seed_copy[i] = seed[i];
    }
    /* Wipes seed_copy. */
    crypto_ed25519_key_pair(secret, public_key, seed_copy);
    wipe(secret, sizeof(secret));
}

static int record_valid(void)
{
    uint8_t derived[32];

    if (stored->magic != KEYSTORE_MAGIC ||
        stored->version != KEYSTORE_VERSION) {
        return 0;
    }

    derive_public_key(derived, stored->seed);
    return bytes_equal(derived, stored->public_key, sizeof(derived));
}

static int generate(void)
{
    union {
        struct key_record record;
        uint32_t words[RECORD_WORDS];
    } fresh;
    uint8_t entropy[64];
    uint8_t hash[64];

    if (!rng_init() || !rng_fill(entropy, sizeof(entropy))) {
        uart_write("WARN RNG_FAILURE\r\n");
        return 0;
    }

    /* Condition 512 bits of hardware entropy into the 256-bit seed. */
    crypto_sha512(hash, entropy, sizeof(entropy));
    wipe(entropy, sizeof(entropy));

    fresh.record.magic = KEYSTORE_MAGIC;
    fresh.record.version = KEYSTORE_VERSION;
    for (uint32_t i = 0u; i < 32u; ++i) {
        fresh.record.seed[i] = hash[i];
    }
    wipe(hash, sizeof(hash));
    derive_public_key(fresh.record.public_key, fresh.record.seed);

    watchdog_kick();
    int ok = flash_erase_sector(KEYSTORE_SECTOR) &&
             flash_program_words(KEYSTORE_ADDRESS + 4u, &fresh.words[1],
                                 RECORD_WORDS - 1u) &&
             flash_program_words(KEYSTORE_ADDRESS, &fresh.words[0], 1u);
    wipe(&fresh, sizeof(fresh));

    if (!ok) {
        uart_write("WARN FLASH_WRITE_FAILED\r\n");
        return 0;
    }
    return record_valid();
}

enum keystore_state keystore_init(void)
{
    if (stored->magic == ERASED_WORD) {
        if (generate()) {
            state = KEYSTORE_READY;
            uart_write("INFO KEY_GENERATED\r\n");
        } else {
            state = KEYSTORE_FAILED;
            uart_write("WARN KEY_GENERATION_FAILED\r\n");
        }
    } else if (record_valid()) {
        state = KEYSTORE_READY;
        uart_write("INFO KEY_LOADED\r\n");
    } else {
        state = KEYSTORE_CORRUPT;
        uart_write("WARN KEY_CORRUPT\r\n");
    }

    return state;
}

int keystore_ready(void)
{
    return state == KEYSTORE_READY;
}

const uint8_t *keystore_seed(void)
{
    return stored->seed;
}

const uint8_t *keystore_public_key(void)
{
    return stored->public_key;
}
