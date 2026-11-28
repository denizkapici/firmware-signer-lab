#include "image.h"

#include <stddef.h>

#include "monocypher-ed25519.h"

static uint32_t read_u32(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

enum image_status image_verify(const uint8_t *slot, uint32_t slot_address,
                               uint32_t slot_size,
                               const uint8_t public_key[32],
                               struct image_info *info)
{
    static const char prefix[] = IMAGE_PREFIX;
    uint8_t message[sizeof(prefix) - 1u + 64u];
    crypto_sha512_ctx hash;

    uint32_t magic = read_u32(slot);
    if (magic == 0xFFFFFFFFu) {
        return IMAGE_EMPTY;
    }
    if (magic != IMAGE_MAGIC ||
        read_u32(slot + 4u) != IMAGE_HEADER_VERSION) {
        return IMAGE_BAD_HEADER;
    }
    for (uint32_t i = 16u; i < IMAGE_SIGNED_HEADER; ++i) {
        if (slot[i] != 0u) {
            return IMAGE_BAD_HEADER;
        }
    }

    uint32_t size = read_u32(slot + 8u);
    if (slot_size <= IMAGE_HEADER_SIZE || size == 0u || (size & 3u) != 0u ||
        size > slot_size - IMAGE_HEADER_SIZE) {
        return IMAGE_BAD_SIZE;
    }

    /* Signature first: nothing else in the image is trusted before it. */
    for (uint32_t i = 0u; i < sizeof(prefix) - 1u; ++i) {
        message[i] = (uint8_t)prefix[i];
    }
    crypto_sha512_init(&hash);
    crypto_sha512_update(&hash, slot, IMAGE_SIGNED_HEADER);
    crypto_sha512_update(&hash, slot + IMAGE_HEADER_SIZE, size);
    crypto_sha512_final(&hash, &message[sizeof(prefix) - 1u]);

    if (crypto_ed25519_check(slot + IMAGE_SIGNED_HEADER, public_key,
                             message, sizeof(message)) != 0) {
        return IMAGE_BAD_SIGNATURE;
    }

    /* A correctly signed image can still be built wrongly; refuse to jump
     * anywhere outside RAM / the image itself. */
    uint32_t stack_pointer = read_u32(slot + IMAGE_HEADER_SIZE);
    uint32_t entry = read_u32(slot + IMAGE_HEADER_SIZE + 4u);
    uint32_t code_start = slot_address + IMAGE_HEADER_SIZE;

    if (stack_pointer < IMAGE_RAM_START + 4u ||
        stack_pointer > IMAGE_RAM_END || (stack_pointer & 7u) != 0u ||
        (entry & 1u) == 0u ||
        (entry & ~1u) < code_start || (entry & ~1u) >= code_start + size) {
        return IMAGE_BAD_VECTORS;
    }

    info->version = read_u32(slot + 12u);
    info->size = size;
    info->stack_pointer = stack_pointer;
    info->entry = entry;
    return IMAGE_OK;
}

const char *image_status_name(enum image_status status)
{
    switch (status) {
    case IMAGE_OK:            return "OK";
    case IMAGE_EMPTY:         return "EMPTY";
    case IMAGE_BAD_HEADER:    return "BAD_HEADER";
    case IMAGE_BAD_SIZE:      return "BAD_SIZE";
    case IMAGE_BAD_SIGNATURE: return "BAD_SIGNATURE";
    case IMAGE_BAD_VECTORS:   return "BAD_VECTORS";
    default:                  return "UNKNOWN";
    }
}
