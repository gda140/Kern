#ifndef SMARTCARD_DELETE_H
#define SMARTCARD_DELETE_H

#include <lvgl.h>

/* Remove one secret from the card. The secret is not read. */
void smartcard_delete_create(lv_obj_t *parent, void (*return_cb)(void));
void smartcard_delete_destroy(void);

#endif
