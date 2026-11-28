ENTRY(Reset_Handler)

/*
 * Application image, started by the bootloader from slot A.
 *
 *   0x08020000  512-byte image header (written by the signing tool)
 *   0x08020200  vector table, then code
 *
 * The vector table must be 512-byte aligned for VTOR (98 entries).
 * See docs/secure-boot.md for the full flash layout.
 */
MEMORY
{
    FLASH (rx)  : ORIGIN = 0x08020200, LENGTH = 128K - 0x200
    RAM   (rwx) : ORIGIN = 0x20000000, LENGTH = 128K
}

INCLUDE sections.ld
