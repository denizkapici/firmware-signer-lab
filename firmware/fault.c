#include <stdint.h>

#include "board.h"
#include "gpio.h"
#include "uart.h"

/*
 * Called from Fault_Entry (startup.s) with a pointer to the stacked
 * exception frame: r0, r1, r2, r3, r12, lr, pc, xpsr.
 *
 * Reports the fault once over UART using polled output, then blinks the
 * LED rapidly. The watchdog is not refreshed here, so the device resets
 * itself after the watchdog timeout instead of hanging forever.
 */
__attribute__((noreturn, used))
void fault_report(const uint32_t *frame)
{
    uart_write_polled("\r\nFAULT pc=");
    uart_write_hex32_polled(frame[6]);
    uart_write_polled(" lr=");
    uart_write_hex32_polled(frame[5]);
    uart_write_polled(" cfsr=");
    uart_write_hex32_polled(SCB_CFSR);
    uart_write_polled(" hfsr=");
    uart_write_hex32_polled(SCB_HFSR);
    uart_write_polled(" bfar=");
    uart_write_hex32_polled(SCB_BFAR);
    uart_write_polled("\r\n");

    for (;;) {
        led_set(1);
        for (volatile uint32_t i = 0u; i < 200000u; ++i) {
        }
        led_set(0);
        for (volatile uint32_t i = 0u; i < 200000u; ++i) {
        }
    }
}
