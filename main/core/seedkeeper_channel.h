/*
 * Seedkeeper secure session on top of the SEC1210.
 *
 * INS 0x81 is sent in the clear. Later commands are wrapped as INS 0x82.
 * The card signs its ephemeral key with itself and with its authentikey; both
 * are checked. The authentikey is the card's identity: until it is one of the
 * paired cards (seedkeeper_pairing.h), the session is open but untrusted and
 * seedkeeper_session_transmit refuses, so no PIN or secret reaches a card
 * the user has not paired. The authentikey signature on an exported secret
 * is not checked: the fingerprint is.
 */

#ifndef SEEDKEEPER_CHANNEL_H
#define SEEDKEEPER_CHANNEL_H

#include "sec1210.h"
#include "seedkeeper_pairing.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

sec1210_err_t seedkeeper_session_open(void);
void seedkeeper_session_close(void);
bool seedkeeper_session_is_open(void);

/* True once the open session's card is paired. */
bool seedkeeper_session_trusted(void);

/* The open session's authentikey, compressed. */
bool seedkeeper_session_card(uint8_t key[SEEDKEEPER_CARD_KEY_LEN]);

/* Pair the open session's card and trust the session. */
seedkeeper_pair_result_t seedkeeper_session_pair(void);

/* Encrypts `apdu`, sends it, and decrypts a 9000 body. Refuses with
 * SEC1210_ERR_ARG while the session is untrusted. On 9C20–9C23 the session is
 * opened once more and, if the card is still a paired one, the command is
 * sent again. A wrong PIN
 * status is returned as-is and is not retried. */
sec1210_err_t seedkeeper_session_transmit(const uint8_t *apdu, size_t apdu_len,
                                          uint8_t *resp, size_t resp_cap,
                                          size_t *resp_len, uint8_t *sw1,
                                          uint8_t *sw2);

#endif
