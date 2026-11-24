#ifndef SIGNER_IMAGE_H
#define SIGNER_IMAGE_H

#include <stdint.h>

/*
 * Signed application image, as stored in a flash slot:
 *
 *   offset 0x000  header (struct image_header, 128 bytes)
 *   offset 0x080  0xFF padding
 *   offset 0x200  application: vector table, code, data (image_size bytes)
 *
 * The signature is Ed25519 over the 79-byte message
 *
 *   "SIGNER-LAB-FW1 " || SHA-512(header bytes 0..63 || application)
 *
 * Header bytes 0..63 are all fields before the signature, so the size and
 * version are covered as well as the code. This file is shared by the
 * bootloader and a host build used by the unit tests.
 */

#define IMAGE_MAGIC          0x49574653u  /* "SFWI" little endian */
#define IMAGE_HEADER_VERSION 1u
#define IMAGE_HEADER_SIZE    0x200u
#define IMAGE_SIGNED_HEADER  64u
#define IMAGE_PREFIX         "SIGNER-LAB-FW1 "

#define IMAGE_RAM_START      0x20000000u
#define IMAGE_RAM_END        0x20020000u

struct image_header {
    uint32_t magic;
    uint32_t header_version;
    uint32_t image_size;      /* bytes after the 0x200 header, multiple of 4 */
    uint32_t image_version;   /* firmware version, used for anti-rollback */
    uint8_t reserved[48];     /* must be zero */
    uint8_t signature[64];
};

enum image_status {
    IMAGE_OK = 0,
    IMAGE_EMPTY,          /* slot erased */
    IMAGE_BAD_HEADER,     /* magic, header version or reserved bytes */
    IMAGE_BAD_SIZE,       /* zero, unaligned or larger than the slot */
    IMAGE_BAD_SIGNATURE,
    IMAGE_BAD_VECTORS     /* stack pointer or entry point out of range */
};

struct image_info {
    uint32_t version;
    uint32_t size;
    uint32_t stack_pointer;
    uint32_t entry;           /* reset handler address (Thumb bit set) */
};

/*
 * Checks the image at `slot` (mapped at run-time address `slot_address`,
 * which may differ from the pointer on the host) against `public_key`.
 * On IMAGE_OK, fills `info`.
 */
enum image_status image_verify(const uint8_t *slot, uint32_t slot_address,
                               uint32_t slot_size,
                               const uint8_t public_key[32],
                               struct image_info *info);

const char *image_status_name(enum image_status status);

#endif
