#ifndef SIGNER_PROTOCOL_H
#define SIGNER_PROTOCOL_H

#include <stdint.h>

/*
 * Line protocol over UART4. A command is printable ASCII terminated by
 * CR, LF or CRLF, at most PROTOCOL_MAX_LINE characters. See
 * docs/approval-protocol.md for the full command list.
 */

#define PROTOCOL_MAX_LINE 255u

/* Feed one received byte. Executes the command at end of line. */
void protocol_feed(uint8_t byte, uint32_t now);

/* Received bytes were lost: reject the current line when it ends. */
void protocol_mark_overflow(void);

#endif
