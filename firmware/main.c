#include <stdint.h>

#include "approval.h"
#include "gpio.h"
#include "keystore.h"
#include "protocol.h"
#include "system.h"
#include "uart.h"

int main(void)
{
    int watchdog_reset = reset_was_watchdog();

    gpio_init();
    uart_init();
    systick_init();
    watchdog_init();

    if (watchdog_reset) {
        uart_write("WARN WATCHDOG_RESET\r\n");
    }
    keystore_init();
    uart_write("Signer firmware started\r\n");

    for (;;) {
        uint8_t byte;

        watchdog_kick();

        if (uart_take_overflow()) {
            protocol_mark_overflow();
        }

        approval_poll(system_milliseconds);

        if (uart_read_byte(&byte)) {
            protocol_feed(byte, system_milliseconds);
            continue;
        }

        /* Sleep until the next interrupt: SysTick (1 ms) or UART RX. */
        __asm volatile ("wfi");
    }
}
