/*
 * Trust on first use for Seedkeeper cards.
 *
 * The card ID is the card's authentikey. It is fixed when the applet is
 * installed, survives a factory reset, and works the same on DIY cards. A
 * card the device has not paired could be a new card or a swapped reader, so
 * the user decides, and the warning is louder once other cards are paired.
 */

#include "smartcard_pair.h"

/* The board guard below needs the config before anything else pulls it in. */
#include "sdkconfig.h"

#if defined(CONFIG_KERN_BOARD_P4_PICO) && !defined(SIMULATOR)

#include "../../core/seedkeeper.h"
#include "../../core/seedkeeper_channel.h"
#include "../../core/seedkeeper_pairing.h"
#include "../../ui/dialog.h"

#include <stdio.h>
#include <string.h>

static void (*next_cb)(void) = NULL;
static void (*refused_cb)(void) = NULL;
static char message[512];

static void finish(bool paired) {
  void (*cb)(void) = paired ? next_cb : refused_cb;
  next_cb = NULL;
  refused_cb = NULL;
  if (cb)
    cb();
}

static void refused_after_info(void *user_data) {
  (void)user_data;
  finish(false);
}

static void full_info(void) {
  snprintf(message, sizeof(message),
           "This device already trusts %d cards. Forget them on the "
           "Smartcard page, then pair this one.",
           SEEDKEEPER_CARDS_MAX);
  dialog_show_info("Too many cards", message, refused_after_info, NULL,
                   DIALOG_STYLE_FULLSCREEN);
}

static void answer(bool confirmed, void *user_data) {
  (void)user_data;
  if (!next_cb && !refused_cb)
    return; /* The page went away while the question was up. */
  if (!confirmed) {
    finish(false);
    return;
  }
  seedkeeper_pair_result_t result = seedkeeper_session_pair();
  if (result == SEEDKEEPER_PAIR_OK) {
    finish(true);
    return;
  }
  if (result == SEEDKEEPER_PAIR_FULL) {
    full_info();
    return;
  }
  dialog_show_info("Not paired", "Could not save the card on this device.",
                   refused_after_info, NULL, DIALOG_STYLE_FULLSCREEN);
}

void smartcard_pair_gate(void (*next)(void), void (*refused)(void)) {
  next_cb = next;
  refused_cb = refused;
  if (seedkeeper_session_trusted()) {
    finish(true);
    return;
  }

  uint8_t key[SEEDKEEPER_CARD_KEY_LEN];
  char id[SEEDKEEPER_CARD_ID_LEN];
  if (!seedkeeper_session_card(key) ||
      !seedkeeper_card_id(key, id, sizeof(id))) {
    finish(false);
    return;
  }
  int count = seedkeeper_pairing_count();
  if (count >= SEEDKEEPER_CARDS_MAX) {
    full_info();
    return;
  }

  if (count == 0) {
    snprintf(message, sizeof(message),
             "New card. Check that this ID matches the authentikey a "
             "Satochip app shows for it on another device.\n\n%s\n\n"
             "Pair this card?",
             id);
    dialog_show_confirm(message, answer, NULL, DIALOG_STYLE_FULLSCREEN);
    return;
  }
  snprintf(message, sizeof(message),
           "Unknown card. It is not one of the %d paired with this device. "
           "If you did not add a card, stop: the card or the reader may have "
           "been swapped.\n\n%s\n\nPair this card?",
           count, id);
  dialog_show_danger_confirm(message, answer, NULL, DIALOG_STYLE_FULLSCREEN);
}

void smartcard_pair_cancel(void) {
  next_cb = NULL;
  refused_cb = NULL;
}

#else

void smartcard_pair_gate(void (*next)(void), void (*refused)(void)) {
  (void)next;
  if (refused)
    refused();
}

void smartcard_pair_cancel(void) {}

#endif
