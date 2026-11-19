#include "flash.h"

#include "board.h"
#include "system.h"

static void unlock(void)
{
    if ((FLASH_CR & FLASH_CR_LOCK) != 0u) {
        FLASH_KEYR = 0x45670123u;
        FLASH_KEYR = 0xCDEF89ABu;
    }
}

static void lock(void)
{
    FLASH_CR = FLASH_CR_LOCK;
}

/* Sector erase takes up to ~0.5 s on a 16 KB sector; keep the watchdog
 * fed while waiting. The CPU stalls on flash reads during the operation,
 * which is acceptable at boot. */
static int wait_idle(void)
{
    while ((FLASH_SR & FLASH_SR_BSY) != 0u) {
        watchdog_kick();
    }

    uint32_t status = FLASH_SR;
    /* Error and EOP flags are cleared by writing 1. */
    FLASH_SR = FLASH_SR_ERRORS | FLASH_SR_EOP;
    return (status & FLASH_SR_ERRORS) == 0u;
}

int flash_erase_sector(uint32_t sector)
{
    if (sector > 11u) {
        return 0;
    }

    unlock();
    if (!wait_idle()) {
        lock();
        return 0;
    }

    FLASH_CR = FLASH_CR_PSIZE_32 | FLASH_CR_SER | (sector << 3);
    FLASH_CR |= FLASH_CR_STRT;
    int ok = wait_idle();

    lock();
    return ok;
}

int flash_program_words(uint32_t address, const uint32_t *words, uint32_t count)
{
    if ((address & 3u) != 0u) {
        return 0;
    }

    unlock();
    int ok = wait_idle();

    FLASH_CR = FLASH_CR_PSIZE_32 | FLASH_CR_PG;
    for (uint32_t i = 0u; ok && i < count; ++i) {
        REG32(address + 4u * i) = words[i];
        ok = wait_idle();
        if (ok && REG32(address + 4u * i) != words[i]) {
            ok = 0;
        }
    }

    lock();
    return ok;
}
