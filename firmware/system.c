#include "system.h"

#include "board.h"

volatile uint32_t system_milliseconds;

void SysTick_Handler(void)
{
    ++system_milliseconds;
}

void systick_init(void)
{
    SYST_CSR = 0u;
    system_milliseconds = 0u;
    SYST_RVR = SIGNER_CORE_CLOCK_HZ / 1000u - 1u;
    SYST_CVR = 0u;
    /* ENABLE | TICKINT | CLKSOURCE (processor clock). */
    SYST_CSR = 7u;
}

void watchdog_init(void)
{
    IWDG_KR = 0xCCCCu;            /* start */
    IWDG_KR = 0x5555u;            /* unlock PR and RLR */
    IWDG_PR = 4u;                 /* LSI 32 kHz / 64 = 500 Hz */
    IWDG_RLR = 2000u;             /* 2000 / 500 Hz = 4 s */
    while ((IWDG_SR & 3u) != 0u) {
    }
    IWDG_KR = 0xAAAAu;            /* reload */
}

void watchdog_kick(void)
{
    IWDG_KR = 0xAAAAu;
}

int reset_was_watchdog(void)
{
    int watchdog = (RCC_CSR & RCC_CSR_IWDGRST) != 0u;
    RCC_CSR |= RCC_CSR_RMVF;
    return watchdog;
}
