#ifndef SMARTCARD_SLOT_H
#define SMARTCARD_SLOT_H

#include <lvgl.h>

enum {
  SMARTCARD_SLOT_NONE = 0,
  SMARTCARD_SLOT_ABSENT,
  SMARTCARD_SLOT_PRESENT,
};

/* Draw the card into body. Repeated calls with the same mark keep the picture. */
void smartcard_slot_show(lv_obj_t *body, int mark);

/* Restore body for a text note and forget the last picture. */
void smartcard_slot_notes(lv_obj_t *body);

void smartcard_slot_reset(void);

#endif
