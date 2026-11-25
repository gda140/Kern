#ifndef SMARTCARD_DESCRIPTOR_H
#define SMARTCARD_DESCRIPTOR_H

#include <lvgl.h>

/* `descriptor` is valid only for the duration of the callback. */
typedef void (*smartcard_descriptor_cb)(const char *descriptor);

/* Read one plaintext Descriptor secret. `return_cb` leaves without one. */
void smartcard_descriptor_load_create(lv_obj_t *parent, void (*return_cb)(void),
                                      smartcard_descriptor_cb loaded_cb);
/* Bring the list back after the caller declines the loaded text. */
void smartcard_descriptor_load_resume(void);
void smartcard_descriptor_load_destroy(void);

/* Store `text`. `label` is the suggested name; the user can change it.
 * The text is copied. */
void smartcard_descriptor_save_create(lv_obj_t *parent, void (*return_cb)(void),
                                      const char *text, const char *label);
void smartcard_descriptor_save_destroy(void);

#endif
