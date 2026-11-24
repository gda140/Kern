/*
 * Seedkeeper secure session on top of the SEC1210.
 *
 * INS 0x81 is sent in the clear. Later commands are wrapped as INS 0x82.
 * The card's self-signature on its ephemeral key is checked. The authentikey
 * signature on an exported secret is not: the fingerprint is.
 */

#ifndef SEEDKEEPER_CHANNEL_H
#define SEEDKEEPER_CHANNEL_H

#include "sec1210.h"

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

sec1210_err_t seedkeeper_session_open(void);
void seedkeeper_session_close(void);
bool seedkeeper_session_is_open(void);

/* Encrypts `apdu`, sends it, and decrypts a 9000 body. On 9C20–9C23 the
 * session is opened once more and the command is sent again. A wrong PIN
 * status is returned as-is and is not retried. */
sec1210_err_t seedkeeper_session_transmit(const uint8_t *apdu, size_t apdu_len,
                                          uint8_t *resp, size_t resp_cap,
                                          size_t *resp_len, uint8_t *sw1,
                                          uint8_t *sw2);

#endif
