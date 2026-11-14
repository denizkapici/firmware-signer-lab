#ifndef SIGNER_APPROVAL_H
#define SIGNER_APPROVAL_H

#include <stdint.h>

/*
 * Approval state machine:
 *
 *   READY --REQUEST2--> PENDING --fresh button press--> APPROVED2 (signed)
 *                          |----CANCEL----------------> CANCELLED2
 *                          |----5 s without press-----> TIMEOUT2
 *
 * A button already held when the request arrives does not count: it must
 * be released and pressed again. Both edges are debounced (20 ms).
 */

#define APPROVAL_TIMEOUT_MS  5000u
#define APPROVAL_DEBOUNCE_MS 20u

int approval_is_pending(void);

/* fields: "<request_id> <digest> <target> <expires_at>".
 * Returns 0 (and changes nothing) if the fields are not canonical V2. */
int approval_start(const char *fields, uint32_t now);

/* Returns 0 if nothing is pending. */
int approval_cancel(void);

/* Call from the main loop. Emits TIMEOUT2 or APPROVED2 when due. */
void approval_poll(uint32_t now);

#endif
