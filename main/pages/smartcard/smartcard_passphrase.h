#ifndef SMARTCARD_PASSPHRASE_H
#define SMARTCARD_PASSPHRASE_H

#include <lvgl.h>

/* `passphrase` is valid only for the duration of the callback. */
typedef void (*smartcard_passphrase_cb)(const char *passphrase);

/* Read one plaintext Password secret. `return_cb` leaves without a secret. */
void smartcard_passphrase_create(lv_obj_t *parent, void (*return_cb)(void),
                                 smartcard_passphrase_cb loaded_cb);
void smartcard_passphrase_destroy(void);

#endif
