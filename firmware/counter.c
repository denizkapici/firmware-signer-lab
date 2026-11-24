#include "counter.h"

#include "board.h"
#include "flash.h"
#include "system.h"

#define ERASED_WORD 0xFFFFFFFFu
#define ENTRY_WORDS 2u

struct log_sector {
    uint32_t sector;
    uint32_t address;
    uint32_t slots;
};

static const struct log_sector sectors[2] = {
    { COUNTER_A_SECTOR, COUNTER_A_ADDRESS, COUNTER_A_SIZE / (4u * ENTRY_WORDS) },
    { COUNTER_B_SECTOR, COUNTER_B_ADDRESS, COUNTER_B_SIZE / (4u * ENTRY_WORDS) },
};

static uint32_t value;
static uint32_t active;     /* index into sectors[] */
static uint32_t next_slot;  /* first never-written slot in the active sector */
static int ready;

static const volatile uint32_t *slot_words(uint32_t log, uint32_t slot)
{
    return (const volatile uint32_t *)(sectors[log].address +
                                       slot * 4u * ENTRY_WORDS);
}

/* A valid entry stores a value and its bitwise complement. Torn writes and
 * partially erased words fail this check and are skipped. */
static int entry_valid(const volatile uint32_t *words, uint32_t *out)
{
    uint32_t stored = words[0];
    if (stored == ERASED_WORD || words[1] != ~stored) {
        return 0;
    }
    *out = stored;
    return 1;
}

static int entry_erased(const volatile uint32_t *words)
{
    return words[0] == ERASED_WORD && words[1] == ERASED_WORD;
}

/* Largest valid value in one sector, and the slot after the last written. */
static void scan(uint32_t log, uint32_t *largest, uint32_t *first_free)
{
    *largest = 0u;
    *first_free = 0u;

    for (uint32_t slot = 0u; slot < sectors[log].slots; ++slot) {
        const volatile uint32_t *words = slot_words(log, slot);
        uint32_t entry;

        if (entry_erased(words)) {
            continue;
        }
        *first_free = slot + 1u;
        if (entry_valid(words, &entry) && entry > *largest) {
            *largest = entry;
        }
    }
}

int counter_init(void)
{
    uint32_t largest[2];
    uint32_t free_slot[2];

    scan(0u, &largest[0], &free_slot[0]);
    scan(1u, &largest[1], &free_slot[1]);

    active = largest[1] > largest[0] ? 1u : 0u;
    value = largest[active];
    next_slot = free_slot[active];
    ready = 1;
    return 1;
}

uint32_t counter_value(void)
{
    return value;
}

static int append(uint32_t log, uint32_t slot, uint32_t entry)
{
    const uint32_t words[ENTRY_WORDS] = { entry, ~entry };
    uint32_t address = sectors[log].address + slot * 4u * ENTRY_WORDS;
    return flash_program_words(address, words, ENTRY_WORDS);
}

int counter_next(uint32_t *next)
{
    if (!ready || value >= COUNTER_MAX) {
        return 0;
    }

    uint32_t candidate = value + 1u;
    watchdog_kick();

    if (next_slot < sectors[active].slots) {
        if (!append(active, next_slot, candidate)) {
            /* The slot may be partly written: never reuse it. */
            ++next_slot;
            return 0;
        }
        ++next_slot;
    } else {
        /* Active sector full: continue in the other one. The old sector
         * keeps its (smaller) entries until it is erased on the next
         * rotation, so a reset at any point still finds the right value. */
        uint32_t other = active ^ 1u;
        if (!flash_erase_sector(sectors[other].sector) ||
            !append(other, 0u, candidate)) {
            return 0;
        }
        active = other;
        next_slot = 1u;
    }

    value = candidate;
    *next = candidate;
    return 1;
}
