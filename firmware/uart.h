#ifndef SIGNER_UART_H
#define SIGNER_UART_H

#include <stdint.h>

/* UART4 on PC10 (TX) / PC11 (RX), 115200 8N1. Reception is interrupt
 * driven into a ring buffer, so bytes are not lost while the main loop is
 * busy (for example while computing a signature). Transmission blocks. */
void uart_init(void);

/* Returns 1 and stores one byte if available, 0 if the buffer is empty. */
int uart_read_byte(uint8_t *byte);

/* Returns 1 once if bytes were dropped since the last call. */
int uart_take_overflow(void);

void uart_write(const char *text);
void uart_write_u32(uint32_t value);  /* canonical decimal */

/* Fault-safe output: polls the hardware directly, no interrupts. */
void uart_write_polled(const char *text);
void uart_write_hex32_polled(uint32_t value);

#endif
