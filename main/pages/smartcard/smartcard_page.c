/*
 * Smartcard page for the ESP32-P4-Pico plus the SEC1210 hat.
 * Probes the reader, powers the card, and reports whether a Seedkeeper
 * applet answers. Import continues on its own screen.
 */

#include "smartcard_page.h"
#include "smartcard_import.h"

#if defined(CONFIG_KERN_BOARD_P4_PICO) && !defined(SIMULATOR)

#include "../../core/seedkeeper.h"
#include "../../ui/input_helpers.h"
#include "../../ui/oneshot.h"
#include "../../ui/theme_widgets.h"
#include "../../utils/session_cleanup.h"
#include "../../utils/worker_task.h"
#include "sec1210.h"

#include <stdio.h>
#include <string.h>

#define PROBE_STACK 16384
#define REPORT_LEN 640

static void (*return_callback)(void) = NULL;
static lv_obj_t *screen = NULL;
static lv_obj_t *body = NULL;
static lv_obj_t *status_label = NULL;
static lv_timer_t *poll_timer = NULL;
static ui_oneshot_t again;
static volatile bool done;
static bool running;
static char report[REPORT_LEN];
static bool offer_import;

static void append(size_t *used, const char *line) {
  if (*used >= REPORT_LEN)
    return;
  int n = snprintf(report + *used, REPORT_LEN - *used, "%s%s",
                   *used ? "\n" : "", line);
  if (n > 0)
    *used += (size_t)n < REPORT_LEN - *used ? (size_t)n : REPORT_LEN - *used - 1;
}

static void hex_line(char *dst, size_t cap, const char *prefix,
                     const uint8_t *bytes, size_t len) {
  size_t used = 0;
  int n = snprintf(dst, cap, "%s", prefix);
  if (n < 0)
    return;
  used = (size_t)n;
  for (size_t i = 0; i < len && used + 3 < cap; i++) {
    n = snprintf(dst + used, cap - used, "%02X", bytes[i]);
    if (n < 0)
      return;
    used += (size_t)n;
  }
}

static void probe(void) {
  size_t used = 0;
  report[0] = '\0';
  offer_import = false;

  sec1210_err_t err = sec1210_init();
  if (err != SEC1210_OK) {
    append(&used, sec1210_err_str(err));
    done = true;
    return;
  }

  sec1210_card_t card = SEC1210_CARD_ABSENT;
  err = sec1210_slot_status(&card);
  if (err != SEC1210_OK) {
    append(&used, sec1210_err_str(err));
    sec1210_deinit();
    done = true;
    return;
  }
  if (card == SEC1210_CARD_ABSENT) {
    append(&used, "Reader answered. No card inserted.");
    sec1210_deinit();
    done = true;
    return;
  }

  uint8_t atr[SEC1210_MAX_ATR];
  size_t atr_len = 0;
  err = sec1210_power_on(atr, sizeof(atr), &atr_len);
  if (err != SEC1210_OK) {
    append(&used, "Card inserted, power-on failed.");
    append(&used, sec1210_err_str(err));
    if (sec1210_last_detail()[0])
      append(&used, sec1210_last_detail());
    sec1210_deinit();
    done = true;
    return;
  }

  char line[96];
  hex_line(line, sizeof(line), "ATR ", atr, atr_len);
  append(&used, line);

  uint8_t apdu[32];
  uint8_t resp[128];
  size_t apdu_len = seedkeeper_apdu_select(apdu, sizeof(apdu));
  size_t resp_len = 0;
  uint8_t sw1 = 0, sw2 = 0;
  err = sec1210_transmit(apdu, apdu_len, resp, sizeof(resp), &resp_len, &sw1,
                         &sw2);
  if (err != SEC1210_OK || sw1 != 0x90 || sw2 != 0x00) {
    if (err != SEC1210_OK)
      snprintf(line, sizeof(line), "Select failed: %s", sec1210_err_str(err));
    else
      snprintf(line, sizeof(line), "Not a Seedkeeper (SW %02X%02X).", sw1, sw2);
    append(&used, line);
    if (err != SEC1210_OK && sec1210_last_detail()[0])
      append(&used, sec1210_last_detail());
    sec1210_power_off();
    sec1210_deinit();
    done = true;
    return;
  }

  apdu_len = seedkeeper_apdu_status(apdu, sizeof(apdu));
  resp_len = 0;
  err = sec1210_transmit(apdu, apdu_len, resp, sizeof(resp), &resp_len, &sw1,
                         &sw2);
  if (err == SEC1210_OK && sw1 == 0x9C && sw2 == 0x04) {
    append(&used, "Seedkeeper found. Card is not set up.");
  } else if (err == SEC1210_OK && sw1 == 0x9C && sw2 == 0x20) {
    append(&used, "Seedkeeper found. A secure session is required to import.");
    offer_import = true;
  } else if (err == SEC1210_OK && sw1 == 0x9C && sw2 == 0x06) {
    append(&used, "Seedkeeper found. The card asked for its PIN.");
    offer_import = true;
  } else if (err != SEC1210_OK || sw1 != 0x90 || sw2 != 0x00) {
    snprintf(line, sizeof(line), "Seedkeeper found. Status failed (SW %02X%02X).",
             sw1, sw2);
    if (err != SEC1210_OK)
      snprintf(line, sizeof(line), "Status failed: %s", sec1210_err_str(err));
    append(&used, line);
  } else {
    seedkeeper_status_t status;
    if (!seedkeeper_status_parse(resp, resp_len, &status)) {
      append(&used, "Seedkeeper found. Status was too short.");
    } else {
      snprintf(line, sizeof(line), "Seedkeeper. %u secrets, %u of %u bytes free.",
               status.nb_secrets, status.free_memory, status.total_memory);
      append(&used, line);
    }
    offer_import = true;
  }

  if (sec1210_power_off() != SEC1210_OK)
    append(&used, "Card power-off failed.");
  sec1210_deinit();
  done = true;
}

static void start_probe(void);

static void again_cb(lv_timer_t *timer) {
  (void)timer;
  start_probe();
}

static void probe_again_event(lv_event_t *e) {
  (void)e;
  ui_oneshot_start(&again, again_cb, 0);
}

static void import_back(void) {
  smartcard_import_destroy();
  smartcard_page_show();
}

static void import_now(lv_timer_t *timer) {
  (void)timer;
  smartcard_page_hide();
  smartcard_import_create(lv_screen_active(), import_back, NULL);
}

static void import_event(lv_event_t *e) {
  (void)e;
  ui_oneshot_start(&again, import_now, 0);
}

static void show_report(void) {
  lv_obj_clean(body);
  status_label =
      theme_create_label(body, report[0] ? report : "No answer.", false);
  lv_obj_set_width(status_label, LV_PCT(100));
  lv_label_set_long_mode(status_label, LV_LABEL_LONG_WRAP);

  if (offer_import) {
    lv_obj_t *import_button =
        theme_create_button(body, "Import a secret", false);
    lv_obj_set_style_margin_top(import_button, theme_default_padding(), 0);
    lv_obj_add_event_cb(import_button, import_event, LV_EVENT_CLICKED, NULL);
  }

  lv_obj_t *button = theme_create_button(body, "Probe again", false);
  lv_obj_set_style_margin_top(button, theme_default_padding(), 0);
  lv_obj_add_event_cb(button, probe_again_event, LV_EVENT_CLICKED, NULL);
}

static void poll_cb(lv_timer_t *timer) {
  (void)timer;
  if (!done)
    return;
  worker_task_wait();
  running = false;
  lv_timer_del(poll_timer);
  poll_timer = NULL;
  show_report();
}

static void start_probe(void) {
  if (running || !body)
    return;
  lv_obj_clean(body);
  status_label = theme_create_label(body, "Talking to the reader...", true);
  report[0] = '\0';
  done = false;
  if (!worker_task_start_io("sec1210", PROBE_STACK, probe, &done)) {
    lv_label_set_text(status_label, "Could not start the probe.");
    return;
  }
  running = true;
  poll_timer = lv_timer_create(poll_cb, 100, NULL);
}

static void back_cb(lv_event_t *e) {
  (void)e;
  if (return_callback)
    return_callback();
}

void smartcard_page_create(lv_obj_t *parent, void (*return_cb)(void)) {
  session_cleanup_register(smartcard_page_destroy);
  return_callback = return_cb;
  screen = theme_create_page_container(parent);
  ui_create_back_button(screen, back_cb);
  theme_create_page_title(screen, "Smartcard");

  int32_t top = theme_corner_button_height() + theme_default_padding();
  body = theme_create_page_container(screen);
  lv_obj_set_size(body, LV_PCT(100), theme_screen_height() - top);
  lv_obj_align(body, LV_ALIGN_BOTTOM_MID, 0, 0);
  lv_obj_set_style_pad_all(body, theme_default_padding(), 0);
  lv_obj_set_style_pad_gap(body, theme_small_padding(), 0);
  lv_obj_set_flex_flow(body, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(body, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER);
  lv_obj_add_flag(body, LV_OBJ_FLAG_SCROLLABLE);

  start_probe();
}

void smartcard_page_show(void) {
  if (screen)
    lv_obj_clear_flag(screen, LV_OBJ_FLAG_HIDDEN);
}

void smartcard_page_hide(void) {
  if (screen)
    lv_obj_add_flag(screen, LV_OBJ_FLAG_HIDDEN);
}

void smartcard_page_destroy(void) {
  session_cleanup_unregister(smartcard_page_destroy);
  smartcard_import_destroy();
  ui_oneshot_cancel(&again);
  if (running) {
    worker_task_wait();
    running = false;
  }
  if (poll_timer) {
    lv_timer_del(poll_timer);
    poll_timer = NULL;
  }
  sec1210_deinit();
  if (screen) {
    lv_obj_del(screen);
    screen = NULL;
  }
  body = NULL;
  status_label = NULL;
  return_callback = NULL;
}

#else

void smartcard_page_create(lv_obj_t *parent, void (*return_cb)(void)) {
  (void)parent;
  (void)return_cb;
}

void smartcard_page_show(void) {}
void smartcard_page_hide(void) {}
void smartcard_page_destroy(void) { smartcard_import_destroy(); }

#endif
