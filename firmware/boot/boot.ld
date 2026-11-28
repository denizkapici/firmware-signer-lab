ENTRY(Reset_Handler)

/*
 * Bootloader: sectors 0-1. Sectors 2-4 hold the counter log and the key
 * store and must never be part of this image.
 */
MEMORY
{
    FLASH (rx)  : ORIGIN = 0x08000000, LENGTH = 32K
    RAM   (rwx) : ORIGIN = 0x20000000, LENGTH = 128K
}

INCLUDE sections.ld
