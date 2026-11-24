#include "passphrase.h"
#include "../core/key.h"
#include "../ui/assets/icons.h"
#include "../ui/dialog.h"
#include "../ui/input_helpers.h"
#include "../ui/theme_widgets.h"
#include "../utils/secure_mem.h"
#include "../utils/session_cleanup.h"
#include "shared/text_input_scan.h"
#include <lvgl.h>
#include <stdio.h>

#if defined(CONFIG_KERN_BOARD_P4_PICO) && !defined(SIMULATOR)
#include "smartcard/smartcard_passphrase.h"
#endif

static lv_obj_t *passphrase_screen = NULL;
static ui_text_input_t text_input = {0};
static void (*return_callback)(void) = NULL;
static passphrase_success_callback_t success_callback = NULL;

static void back_confirm_cb(bool result, void *user_data) {
  (void)user_data;
  if (result && return_callback)
    return_callback();
}

static void back_btn_cb(lv_event_t *e) {
  (void)e;
  dialog_show_confirm("Are you sure you want to go back?", back_confirm_cb,
                      NULL, DIALOG_STYLE_OVERLAY);
}

static void confirm_passphrase_cb(bool result, void *user_data) {
  (void)user_data;
  if (result && success_callback)
    success_callback(lv_textarea_get_text(text_input.textarea));
}

static void scan_key_cb(void *user_data) {
  (void)user_data;
  text_input_scan_cfg_t cfg = {&text_input, passphrase_page_hide,
                               passphrase_page_show, NULL};
  text_input_scan_start(&cfg);
}

#if defined(CONFIG_KERN_BOARD_P4_PICO) && !defined(SIMULATOR)
static void keyboard_ready_cb(lv_event_t *e);

static void seedkeeper_back(void) {
  smartcard_passphrase_destroy();
  passphrase_page_show();
}

static void seedkeeper_loaded(const char *passphrase) {
  if (text_input.textarea && passphrase)
    lv_textarea_set_text(text_input.textarea, passphrase);
  passphrase_page_show();
  keyboard_ready_cb(NULL);
}

static void from_seedkeeper_cb(lv_event_t *e) {
  (void)e;
  passphrase_page_hide();
  smartcard_passphrase_create(lv_screen_active(), seedkeeper_back,
                              seedkeeper_loaded);
}
#endif

static void keyboard_ready_cb(lv_event_t *e) {
  (void)e;

  const char *text = lv_textarea_get_text(text_input.textarea);
  const char *passphrase = (text && text[0] != '\0') ? text : NULL;

  // A typo looks like plausible dots either way; only the fingerprint it
  // derives makes it visible, without putting the secret on screen.
  char before_hex[BIP32_KEY_FINGERPRINT_LEN * 2 + 1];
  char after_hex[BIP32_KEY_FINGERPRINT_LEN * 2 + 1];
  char *mnemonic = NULL;
  if (!key_get_fingerprint_hex(before_hex) || !key_get_mnemonic(&mnemonic))
    return;
  bool ok =
      key_mnemonic_passphrase_fingerprint_hex(mnemonic, passphrase, after_hex);
  SECURE_FREE_STRING(mnemonic);
  if (!ok)
    return;

  lv_color32_t c = lv_color_to_32(highlight_color(), LV_OPA_COVER);
  uint32_t highlight = (c.red << 16) | (c.green << 8) | c.blue;

  char prompt[128];
  snprintf(prompt, sizeof(prompt),
           "Confirm passphrase?\n\n" ICON_FINGERPRINT " %s\n" LV_SYMBOL_DOWN
           "\n#%06X " ICON_FINGERPRINT " %s#",
           before_hex, (unsigned)highlight, after_hex);
  dialog_show_confirm(prompt, confirm_passphrase_cb, NULL,
                      DIALOG_STYLE_OVERLAY);
}

void passphrase_page_create(lv_obj_t *parent, void (*return_cb)(void),
                            passphrase_success_callback_t success_cb) {
  session_cleanup_register(passphrase_page_destroy);
  (void)parent;
  return_callback = return_cb;
  success_callback = success_cb;

  // Screen
  passphrase_screen = theme_create_page_container(lv_screen_active());

  // Create title label
  theme_create_page_title(passphrase_screen, "Enter Passphrase");

  // Back button
  ui_create_back_button(passphrase_screen, back_btn_cb);

  // Text input (textarea + keyboard), masked with an eye toggle to reveal
  ui_text_input_create(&text_input, passphrase_screen, "passphrase", true,
                       keyboard_ready_cb);
  ui_text_input_enable_scan(&text_input, scan_key_cb, NULL);

#if defined(CONFIG_KERN_BOARD_P4_PICO) && !defined(SIMULATOR)
  lv_obj_t *card_btn =
      theme_create_button(passphrase_screen, "From Seedkeeper", false);
  lv_obj_set_width(card_btn, LV_PCT(80));
  lv_obj_align_to(card_btn, text_input.textarea, LV_ALIGN_OUT_BOTTOM_LEFT, 0,
                  theme_default_padding());
  lv_obj_add_event_cb(card_btn, from_seedkeeper_cb, LV_EVENT_CLICKED, NULL);
#endif
}

void passphrase_page_show(void) {
  if (passphrase_screen)
    lv_obj_clear_flag(passphrase_screen, LV_OBJ_FLAG_HIDDEN);
  if (text_input.keyboard)
    lv_obj_clear_flag(text_input.keyboard, LV_OBJ_FLAG_HIDDEN);
}

void passphrase_page_hide(void) {
  if (passphrase_screen)
    lv_obj_add_flag(passphrase_screen, LV_OBJ_FLAG_HIDDEN);
  if (text_input.keyboard)
    lv_obj_add_flag(text_input.keyboard, LV_OBJ_FLAG_HIDDEN);
}

void passphrase_page_destroy(void) {
  session_cleanup_unregister(passphrase_page_destroy);
#if defined(CONFIG_KERN_BOARD_P4_PICO) && !defined(SIMULATOR)
  smartcard_passphrase_destroy();
#endif
  ui_text_input_destroy(&text_input);
  if (passphrase_screen) {
    lv_obj_del(passphrase_screen);
    passphrase_screen = NULL;
  }
  return_callback = NULL;
  success_callback = NULL;
}
