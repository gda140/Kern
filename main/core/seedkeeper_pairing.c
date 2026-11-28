#include "seedkeeper_pairing.h"
#include "settings.h"

#include <string.h>

#define LIST_CAP (SEEDKEEPER_CARDS_MAX * SEEDKEEPER_CARD_KEY_LEN)

/* A list that cannot be read or does not parse counts as empty: the user is
 * then asked to pair again, which fails safe. */
static size_t load(uint8_t list[LIST_CAP]) {
  size_t len = LIST_CAP;
  if (settings_get_seedkeeper_cards(list, &len) != ESP_OK ||
      !seedkeeper_cards_valid(list, len))
    return 0;
  return len / SEEDKEEPER_CARD_KEY_LEN;
}

int seedkeeper_pairing_count(void) {
  uint8_t list[LIST_CAP];
  return (int)load(list);
}

bool seedkeeper_pairing_known(const uint8_t key[SEEDKEEPER_CARD_KEY_LEN]) {
  uint8_t list[LIST_CAP];
  size_t count = load(list);
  return seedkeeper_cards_find(list, count, key) >= 0;
}

seedkeeper_pair_result_t
seedkeeper_pairing_add(const uint8_t key[SEEDKEEPER_CARD_KEY_LEN]) {
  if (!key || (key[0] != 0x02 && key[0] != 0x03))
    return SEEDKEEPER_PAIR_FAILED;
  uint8_t list[LIST_CAP];
  size_t count = load(list);
  if (seedkeeper_cards_find(list, count, key) >= 0)
    return SEEDKEEPER_PAIR_OK;
  if (count >= SEEDKEEPER_CARDS_MAX)
    return SEEDKEEPER_PAIR_FULL;
  memcpy(list + count * SEEDKEEPER_CARD_KEY_LEN, key, SEEDKEEPER_CARD_KEY_LEN);
  count++;
  if (settings_set_seedkeeper_cards(list, count * SEEDKEEPER_CARD_KEY_LEN) !=
      ESP_OK)
    return SEEDKEEPER_PAIR_FAILED;
  /* Read back: a key that did not stick must not open the session. */
  return seedkeeper_pairing_known(key) ? SEEDKEEPER_PAIR_OK
                                       : SEEDKEEPER_PAIR_FAILED;
}

bool seedkeeper_pairing_forget_all(void) {
  return settings_set_seedkeeper_cards(NULL, 0) == ESP_OK &&
         seedkeeper_pairing_count() == 0;
}
