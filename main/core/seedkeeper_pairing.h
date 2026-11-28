/*
 * Seedkeeper cards this device trusts, by authentikey.
 *
 * The secure channel proves which authentikey the card holds. The first time
 * a card is seen the user checks its ID and pairs it; later sessions with any
 * other authentikey are refused before the card PIN is sent. The list lives
 * in the settings namespace, so a device wipe forgets it.
 */

#ifndef SEEDKEEPER_PAIRING_H
#define SEEDKEEPER_PAIRING_H

#include "seedkeeper.h"

#include <stdbool.h>
#include <stdint.h>

typedef enum {
  SEEDKEEPER_PAIR_OK = 0,
  SEEDKEEPER_PAIR_FULL,
  SEEDKEEPER_PAIR_FAILED,
} seedkeeper_pair_result_t;

/* Number of paired cards, 0 if none or the list cannot be read. */
int seedkeeper_pairing_count(void);

bool seedkeeper_pairing_known(const uint8_t key[SEEDKEEPER_CARD_KEY_LEN]);

/* Adding a key already in the list is OK. */
seedkeeper_pair_result_t
seedkeeper_pairing_add(const uint8_t key[SEEDKEEPER_CARD_KEY_LEN]);

bool seedkeeper_pairing_forget_all(void);

#endif
