// Backup Menu Page

#include "backup_menu.h"
#include "../../../ui/assets/icons.h"
#include "../../../ui/dialog.h"
#include "../../../ui/menu.h"
#include "../../../ui/theme_widgets.h"
#include "../../../utils/session_cleanup.h"
#include "mnemonic_qr.h"
#include "mnemonic_words.h"
#include <lvgl.h>

#if defined(CONFIG_KERN_BOARD_P4_PICO) && !defined(SIMULATOR)
#include "../../smartcard/smartcard_save.h"
#endif

static ui_menu_t *backup_menu = NULL;
static lv_obj_t *backup_menu_screen = NULL;
static void (*return_callback)(void) = NULL;

/* --- Words / QR Code callbacks --- */

static void return_from_mnemonic_words_cb(void) {
  mnemonic_words_page_destroy();
  backup_menu_page_show();
}

static void return_from_mnemonic_qr_cb(void) {
  mnemonic_qr_page_destroy();
  backup_menu_page_show();
}

static void (*pending_action)(void) = NULL;

static void launch_words(void) {
  mnemonic_words_page_create(lv_screen_active(), return_from_mnemonic_words_cb);
  mnemonic_words_page_show();
}

static void launch_qr(void) {
  mnemonic_qr_page_create(lv_screen_active(), return_from_mnemonic_qr_cb);
  mnemonic_qr_page_show();
}

static void danger_confirm_cb(bool confirmed, void *user_data) {
  (void)user_data;
  if (!confirmed)
    return;
  backup_menu_page_hide();
  pending_action();
}

static void warn_and_launch(void (*action)(void)) {
  pending_action = action;
  dialog_show_danger_confirm(DIALOG_SENSITIVE_DATA_WARNING, danger_confirm_cb,
                             NULL, DIALOG_STYLE_OVERLAY);
}

static void menu_words_cb(void) { warn_and_launch(launch_words); }

static void menu_qr_cb(void) { warn_and_launch(launch_qr); }

#if defined(CONFIG_KERN_BOARD_P4_PICO) && !defined(SIMULATOR)
static void seedkeeper_back(void) {
  smartcard_save_destroy();
  backup_menu_page_show();
}

static void menu_seedkeeper_cb(void) {
  backup_menu_page_hide();
  smartcard_save_create(lv_screen_active(), seedkeeper_back);
}
#endif

/* --- Back --- */

static void back_cb(void) {
  if (return_callback) {
    return_callback();
  }
}

void backup_menu_page_create(lv_obj_t *parent, void (*return_cb)(void)) {
  session_cleanup_register(backup_menu_page_destroy);
  if (!parent)
    return;

  return_callback = return_cb;

  backup_menu_screen = theme_create_page_container(parent);

  backup_menu = ui_menu_create(backup_menu_screen, "Back Up", back_cb);
  if (!backup_menu)
    return;

  ui_menu_add_entry_with_icon(backup_menu, LV_SYMBOL_LIST, "Words",
                              menu_words_cb);
  ui_menu_add_entry_with_icon(backup_menu, ICON_QR_CODE, "QR Code", menu_qr_cb);
#if defined(CONFIG_KERN_BOARD_P4_PICO) && !defined(SIMULATOR)
  ui_menu_add_entry_with_icon(backup_menu, ICON_KEY, "To Seedkeeper",
                              menu_seedkeeper_cb);
#endif
}

void backup_menu_page_show(void) {
  if (backup_menu_screen) {
    lv_obj_clear_flag(backup_menu_screen, LV_OBJ_FLAG_HIDDEN);
  }
  if (backup_menu) {
    ui_menu_show(backup_menu);
  }
}

void backup_menu_page_hide(void) {
  if (backup_menu_screen) {
    lv_obj_add_flag(backup_menu_screen, LV_OBJ_FLAG_HIDDEN);
  }
  if (backup_menu) {
    ui_menu_hide(backup_menu);
  }
}

void backup_menu_page_destroy(void) {
  session_cleanup_unregister(backup_menu_page_destroy);
#if defined(CONFIG_KERN_BOARD_P4_PICO) && !defined(SIMULATOR)
  smartcard_save_destroy();
#endif
  if (backup_menu) {
    ui_menu_destroy(backup_menu);
    backup_menu = NULL;
  }

  if (backup_menu_screen) {
    lv_obj_del(backup_menu_screen);
    backup_menu_screen = NULL;
  }

  return_callback = NULL;
}
