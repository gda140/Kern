#ifndef SMARTCARD_SAVE_H
#define SMARTCARD_SAVE_H

#include <lvgl.h>

/* Write the loaded BIP39 mnemonic onto the Seedkeeper. `return_cb` runs
 * when the user leaves the page. */
void smartcard_save_create(lv_obj_t *parent, void (*return_cb)(void));
void smartcard_save_destroy(void);

#endif
