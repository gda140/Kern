#ifndef SMARTCARD_PAGE_H
#define SMARTCARD_PAGE_H

#include <lvgl.h>

void smartcard_page_create(lv_obj_t *parent, void (*return_cb)(void));
void smartcard_page_show(void);
void smartcard_page_hide(void);
void smartcard_page_destroy(void);

#endif
