#ifndef SMARTCARD_IMPORT_H
#define SMARTCARD_IMPORT_H

#include <lvgl.h>

/* `loaded_cb` runs after the secret is in the wallet. NULL tears down the
 * Settings smartcard flow and opens Home. */
void smartcard_import_create(lv_obj_t *parent, void (*return_cb)(void),
                             void (*loaded_cb)(void));
void smartcard_import_destroy(void);

#endif
