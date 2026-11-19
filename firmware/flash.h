#ifndef SIGNER_FLASH_H
#define SIGNER_FLASH_H

#include <stdint.h>

/* STM32F4 embedded flash programming (2.7-3.6 V, 32-bit parallelism).
 * Both functions unlock the controller, wait for completion, lock it
 * again and return 1 on success, 0 on a reported error. */
int flash_erase_sector(uint32_t sector);
int flash_program_words(uint32_t address, const uint32_t *words, uint32_t count);

#endif
