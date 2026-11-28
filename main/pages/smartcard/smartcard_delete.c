/*
 * Delete one secret from a Seedkeeper.
 *
 * The card PIN is a 4–16 byte string. A wrong PIN is sent once: the card
 * counts the try. The list shows labels only. Reset (INS 0xA5) does not
 * read the secret. The card's authentikey certificate is not offered.
 */

#include "smartcard_delete.h"
#include "smartcard_pair.h"
#include "smartcard_slot.h"

#if defined(CONFIG_KERN_BOARD_P4_PICO) && !defined(SIMULATOR)

#include "../../core/seedkeeper.h"
#include "../../core/seedkeeper_channel.h"
#include "../../ui/dialog.h"
#include "../../ui/input_helpers.h"
#include "../../ui/menu.h"
#include "../../ui/oneshot.h"
#include "../../ui/theme_widgets.h"
#include "../../utils/secure_mem.h"
#include "../../utils/session_cleanup.h"
#include "../../utils/worker_task.h"
#include "sec1210.h"

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <stdio.h>
#include <string.h>

#define DELETE_STACK (48 * 1024)
#define MAX_SECRETS 16

enum { JOB_OPEN, JOB_PIN, JOB_LIST, JOB_RESET, JOB_WATCH };

static void (*return_callback)(void) = NULL;
static lv_obj_t *screen = NULL;
static lv_obj_t *title = NULL;
static lv_obj_t *back_btn = NULL;
static lv_obj_t *body = NULL;
static lv_obj_t *pin_host = NULL;
static lv_timer_t *poll_timer = NULL;
static lv_timer_t *watch_timer = NULL;
static lv_timer_t *retry_timer = NULL;
static lv_obj_t *loading_spinner = NULL;
static int retry_countdown = 0;
static lv_obj_t *retry_label = NULL;
static volatile bool card_present;
static ui_oneshot_t defer;
static ui_text_input_t pin_input;
static ui_menu_t *secret_menu = NULL;
static volatile bool done;
static bool running;
static bool reader_up;
static int job;
static bool job_ok;
static bool ask_pin;
static char note[192];
static uint8_t pin[SEEDKEEPER_PIN_MAX];
static size_t pin_len;
static seedkeeper_header_t secrets[MAX_SECRETS];
static int secret_count;
static int skipped_authentikey;
static bool list_truncated;
static int reset_index;
static sec1210_err_t io_err;
static uint8_t sw1, sw2;

static void stop_watch(void) {
  if (!watch_timer)
    return;
  lv_timer_del(watch_timer);
  watch_timer = NULL;
}

static void cancel_retry_timer(void) {
  if (retry_timer) {
    lv_timer_del(retry_timer);
    retry_timer = NULL;
  }
  retry_label = NULL;
}

static void show_loading_spinner(void) {
  if (!screen || loading_spinner)
    return;
  loading_spinner = lv_spinner_create(screen);
  theme_apply_spinner(loading_spinner);
  lv_obj_set_size(loading_spinner, 36, 36);
  lv_spinner_set_anim_params(loading_spinner, 1000, 60);
  lv_obj_add_flag(loading_spinner, LV_OBJ_FLAG_FLOATING);
  lv_obj_align(loading_spinner, LV_ALIGN_TOP_MID, 0,
               theme_corner_button_height());
}

static void hide_loading_spinner(void) {
  if (loading_spinner) {
    lv_obj_del(loading_spinner);
    loading_spinner = NULL;
  }
}

static void start_job(int which, const char *status);

static void retry_countdown_cb(lv_timer_t *timer) {
  (void)timer;
  retry_countdown--;
  if (retry_countdown <= 0) {
    cancel_retry_timer();
    start_job(JOB_OPEN, "Opening a secure session...");
    return;
  }
  if (retry_label) {
    char buf[32];
    snprintf(buf, sizeof(buf), "Retrying in %ds...", retry_countdown);
    lv_label_set_text(retry_label, buf);
  }
}

static void reader_down(void) {
  seedkeeper_session_close();
  if (!reader_up)
    return;
  if (sec1210_power_off() != SEC1210_OK) {
    /* Closing the UART is the useful part once power-off has failed. */
  }
  sec1210_deinit();
  reader_up = false;
}

static void chrome(bool on) {
  if (back_btn) {
    if (on)
      lv_obj_clear_flag(back_btn, LV_OBJ_FLAG_HIDDEN);
    else
      lv_obj_add_flag(back_btn, LV_OBJ_FLAG_HIDDEN);
  }
  if (title) {
    if (on)
      lv_obj_clear_flag(title, LV_OBJ_FLAG_HIDDEN);
    else
      lv_obj_add_flag(title, LV_OBJ_FLAG_HIDDEN);
  }
}

static void show_menu(void);
static void list_now(lv_timer_t *timer);

static void list_button_cb(lv_event_t *e) {
  (void)e;
  ui_oneshot_start(&defer, list_now, 0);
}

static void show_slot(int mark) {
  if (!body)
    return;
  if (secret_menu)
    ui_menu_hide(secret_menu);
  chrome(true);
  if (title)
    lv_label_set_text(title, "Delete");
  smartcard_slot_show(body, mark);
}

static void show_note(bool list_button) {
  smartcard_slot_notes(body);
  chrome(true);
  if (title)
    lv_label_set_text(title, "Delete");
  if (secret_menu)
    ui_menu_hide(secret_menu);
  lv_obj_clean(body);
  lv_obj_clear_flag(body, LV_OBJ_FLAG_HIDDEN);
  const char *text = note[0] ? note : sec1210_err_str(io_err);
  if (!note[0] && io_err == SEC1210_OK)
    text = "The card did not accept the command.";
  lv_obj_t *label = theme_create_label(body, text, false);
  lv_obj_set_width(label, LV_PCT(100));
  lv_label_set_long_mode(label, LV_LABEL_LONG_WRAP);
  if (list_button && seedkeeper_session_is_open()) {
    lv_obj_t *button = theme_create_button(body, "Back to the list", false);
    lv_obj_set_style_margin_top(button, theme_default_padding(), 0);
    lv_obj_add_event_cb(button, list_button_cb, LV_EVENT_CLICKED, NULL);
  }
}

static void note_sw(const char *what) {
  int tries = 0;
  ask_pin = false;
  if (seedkeeper_pin_tries_left(sw1, sw2, &tries)) {
    snprintf(note, sizeof(note), "Wrong PIN. %d %s left.", tries,
             tries == 1 ? "try" : "tries");
    ask_pin = true;
    return;
  }
  if (sw1 == 0x9C && sw2 == 0x02) {
    snprintf(note, sizeof(note), "Wrong PIN.");
    ask_pin = true;
    return;
  }
  if (sw1 == 0x9C && sw2 == 0x06) {
    snprintf(note, sizeof(note), "The card still wants the PIN.");
    ask_pin = true;
    return;
  }
  if (sw1 == 0x9C && sw2 == 0x0C) {
    snprintf(note, sizeof(note), "PIN is blocked.");
    return;
  }
  if (sw1 == 0x9C && sw2 == 0x03) {
    snprintf(note, sizeof(note), "The card refused to delete this secret.");
    return;
  }
  if (sw1 == 0x9C && sw2 == 0x08) {
    snprintf(note, sizeof(note), "The card did not find that secret.");
    return;
  }
  if (sw1 == 0x9C && sw2 >= 0x20 && sw2 <= 0x23) {
    snprintf(note, sizeof(note), "The secure session was rejected.");
    return;
  }
  snprintf(note, sizeof(note), "%s (SW %02X%02X).", what, sw1, sw2);
}

static bool status_ok(void) {
  return io_err == SEC1210_OK && sw1 == 0x90 && sw2 == 0x00;
}

static void job_open(void) {
  card_present = false;
  io_err = sec1210_init();
  if (io_err != SEC1210_OK)
    return;
  reader_up = true;

  sec1210_card_t card = SEC1210_CARD_ABSENT;
  io_err = sec1210_slot_status(&card);
  if (io_err != SEC1210_OK)
    return;
  if (card == SEC1210_CARD_ABSENT) {
    snprintf(note, sizeof(note), "No card inserted.");
    io_err = SEC1210_ERR_CARD;
    return;
  }
  card_present = true;

  /* The card generates a key for the session. That sometimes fails on the
   * first try. Power-cycle and repeat. A wrong PIN is not on this path. */
  bool session_failed = false;
  for (int attempt = 0; attempt < 3; attempt++) {
    if (attempt > 0)
      vTaskDelay(pdMS_TO_TICKS(300));

    uint8_t atr[SEC1210_MAX_ATR];
    size_t atr_len = 0;
    io_err = sec1210_power_on(atr, sizeof(atr), &atr_len);
    if (io_err != SEC1210_OK)
      continue;

    uint8_t apdu[32];
    uint8_t resp[256];
    size_t resp_len = 0;
    size_t apdu_len = seedkeeper_apdu_select(apdu, sizeof(apdu));
    io_err = sec1210_transmit(apdu, apdu_len, resp, sizeof(resp), &resp_len,
                              &sw1, &sw2);
    secure_memzero(resp, sizeof(resp));
    if (io_err != SEC1210_OK)
      continue;
    if (!status_ok()) {
      note_sw("Select failed");
      return;
    }
    io_err = seedkeeper_session_open();
    if (io_err == SEC1210_OK) {
      job_ok = true;
      return;
    }
    session_failed = true;
    sec1210_power_off();
  }
  if (session_failed && !note[0])
    snprintf(note, sizeof(note), "Could not open a secure session.");
}

static void job_pin(void) {
  uint8_t apdu[5 + SEEDKEEPER_PIN_MAX];
  uint8_t resp[64];
  size_t resp_len = 0;
  size_t apdu_len =
      seedkeeper_apdu_verify_pin(pin, pin_len, apdu, sizeof(apdu));
  secure_memzero(pin, sizeof(pin));
  pin_len = 0;
  if (!apdu_len) {
    io_err = SEC1210_ERR_ARG;
    snprintf(note, sizeof(note), "The PIN is 4 to 16 characters.");
    return;
  }
  io_err = seedkeeper_session_transmit(apdu, apdu_len, resp, sizeof(resp),
                                       &resp_len, &sw1, &sw2);
  secure_memzero(apdu, sizeof(apdu));
  secure_memzero(resp, sizeof(resp));
  if (io_err != SEC1210_OK)
    return;
  if (status_ok())
    job_ok = true;
  else
    note_sw("PIN rejected");
}

static void job_list(void) {
  secret_count = 0;
  skipped_authentikey = 0;
  list_truncated = false;
  uint8_t p2 = SEEDKEEPER_P2_INIT;
  for (int i = 0; i < 32; i++) {
    uint8_t apdu[8];
    uint8_t resp[256];
    size_t resp_len = 0;
    size_t apdu_len = seedkeeper_apdu_list(p2, apdu, sizeof(apdu));
    io_err = seedkeeper_session_transmit(apdu, apdu_len, resp, sizeof(resp),
                                         &resp_len, &sw1, &sw2);
    if (io_err != SEC1210_OK) {
      secure_memzero(resp, sizeof(resp));
      return;
    }
    if (sw1 == 0x9C && sw2 == 0x12) {
      secure_memzero(resp, sizeof(resp));
      job_ok = true;
      return;
    }
    if (!status_ok()) {
      note_sw("List failed");
      secure_memzero(resp, sizeof(resp));
      return;
    }
    seedkeeper_header_t header;
    if (seedkeeper_header_parse(resp, resp_len, &header)) {
      if (header.type == SEEDKEEPER_TYPE_AUTHENTIKEY)
        skipped_authentikey++;
      else if (seedkeeper_can_delete(&header)) {
        if (secret_count < MAX_SECRETS)
          secrets[secret_count++] = header;
        else
          list_truncated = true;
      }
    }
    secure_memzero(&header, sizeof(header));
    secure_memzero(resp, sizeof(resp));
    p2 = SEEDKEEPER_P2_NEXT;
  }
  snprintf(note, sizeof(note), "The card kept listing secrets.");
  io_err = SEC1210_ERR_PROTO;
}

static void job_reset(void) {
  if (reset_index < 0 || reset_index >= secret_count) {
    io_err = SEC1210_ERR_ARG;
    return;
  }
  uint8_t apdu[8];
  uint8_t resp[32];
  size_t resp_len = 0;
  size_t apdu_len =
      seedkeeper_apdu_reset(secrets[reset_index].id, apdu, sizeof(apdu));
  io_err = seedkeeper_session_transmit(apdu, apdu_len, resp, sizeof(resp),
                                       &resp_len, &sw1, &sw2);
  secure_memzero(apdu, sizeof(apdu));
  secure_memzero(resp, sizeof(resp));
  if (io_err != SEC1210_OK)
    return;
  if (status_ok())
    job_ok = true;
  else
    note_sw("Delete failed");
}

static void job_watch(void) {
  card_present = false;
  if (!reader_up) {
    io_err = sec1210_init();
    if (io_err != SEC1210_OK)
      return;
    reader_up = true;
  }
  sec1210_card_t card = SEC1210_CARD_ABSENT;
  io_err = sec1210_slot_status(&card);
  card_present = io_err == SEC1210_OK && card != SEC1210_CARD_ABSENT;
}

static void worker(void) {
  if (job == JOB_WATCH) {
    job_watch();
    return;
  }
  job_ok = false;
  ask_pin = false;
  note[0] = '\0';
  sw1 = 0;
  sw2 = 0;
  io_err = SEC1210_OK;
  if (job == JOB_OPEN)
    job_open();
  else if (job == JOB_PIN)
    job_pin();
  else if (job == JOB_LIST)
    job_list();
  else
    job_reset();
}

static void show_pin(void);
static void clear_pin_ui(void);

/* The keyboard is a later sibling and would cover the error modal. */
static void show_pin_after_error(void) {
  if (screen)
    show_pin();
}

static void watch_tick(lv_timer_t *timer) {
  (void)timer;
  if (!screen || running)
    return;
  start_job(JOB_WATCH, NULL);
}

static void start_watch(void) {
  if (watch_timer || !screen)
    return;
  watch_timer = lv_timer_create(watch_tick, 500, NULL);
}

/* The card is not paired: nothing, not even its PIN, was sent to it. */
static void pair_refused(void) {
  snprintf(note, sizeof(note), "Card not paired. Its PIN was not sent.");
  io_err = SEC1210_OK;
  show_note(false);
  reader_down();
}

static void after_open(void) {
  hide_loading_spinner();
  if (!job_ok) {
    if (strcmp(note, "No card inserted.") == 0) {
      show_slot(SMARTCARD_SLOT_ABSENT);
      start_watch();
      return;
    }
    show_note(false);
    stop_watch();
    reader_down();
    if (io_err != SEC1210_OK) {
      retry_countdown = 5;
      retry_label = theme_create_label(body, "Retrying in 5s...", false);
      lv_obj_set_width(retry_label, LV_PCT(100));
      retry_timer = lv_timer_create(retry_countdown_cb, 1000, NULL);
    }
    return;
  }
  stop_watch();
  smartcard_pair_gate(show_pin, pair_refused);
}

static void after_pin(void) {
  if (ask_pin) {
    clear_pin_ui();
    dialog_show_error_timeout(note, show_pin_after_error, 0);
    return;
  }
  if (!job_ok) {
    show_note(false);
    if (io_err != SEC1210_OK || (sw1 == 0x9C && sw2 == 0x0C))
      reader_down();
    return;
  }
  start_job(JOB_LIST, "Reading the list...");
}

static void after_list(void) {
  if (ask_pin) {
    clear_pin_ui();
    dialog_show_error_timeout(note, show_pin_after_error, 0);
    return;
  }
  if (!job_ok) {
    show_note(false);
    if (io_err != SEC1210_OK)
      reader_down();
    return;
  }
  if (secret_count == 0) {
    if (skipped_authentikey)
      snprintf(note, sizeof(note),
               "The card's own certificate stays. There is no other secret "
               "to delete.");
    else
      snprintf(note, sizeof(note), "The card has no secret to delete.");
    show_note(false);
    return;
  }
  show_menu();
}

static void drop_reset_secret(void) {
  if (reset_index < 0 || reset_index >= secret_count)
    return;
  memmove(&secrets[reset_index], &secrets[reset_index + 1],
          (size_t)(secret_count - reset_index - 1) * sizeof(secrets[0]));
  secret_count--;
  secure_memzero(&secrets[secret_count], sizeof(secrets[0]));
  reset_index = -1;
}

static void after_deleted(void *user_data) {
  (void)user_data;
  if (!screen)
    return;
  if (secret_count == 0) {
    if (skipped_authentikey)
      snprintf(
          note, sizeof(note),
          "The card's own certificate stays. Nothing else is on the card.");
    else
      snprintf(note, sizeof(note), "Nothing else is on the card.");
    io_err = SEC1210_OK;
    show_note(false);
    return;
  }
  show_menu();
}

static void after_reset(void) {
  if (ask_pin) {
    clear_pin_ui();
    dialog_show_error_timeout(note, show_pin_after_error, 0);
    return;
  }
  if (!job_ok) {
    bool keep = io_err == SEC1210_OK && seedkeeper_session_is_open();
    show_note(keep);
    if (!keep)
      reader_down();
    return;
  }
  drop_reset_secret();
  dialog_show_info("Deleted", "The secret was removed from the card.",
                   after_deleted, NULL, DIALOG_STYLE_OVERLAY);
}

static void poll_cb(lv_timer_t *timer) {
  (void)timer;
  if (!done) {
    if (job == JOB_OPEN && card_present)
      show_slot(SMARTCARD_SLOT_PRESENT);
    return;
  }
  worker_task_wait();
  running = false;
  lv_timer_del(poll_timer);
  poll_timer = NULL;
  if (job == JOB_WATCH) {
    if (card_present && screen)
      start_job(JOB_OPEN, "Opening a secure session...");
    return;
  }
  if (job == JOB_OPEN)
    after_open();
  else if (job == JOB_PIN)
    after_pin();
  else if (job == JOB_LIST)
    after_list();
  else
    after_reset();
}

static void start_job(int which, const char *status) {
  if (running || !body)
    return;
  cancel_retry_timer();
  hide_loading_spinner();
  job = which;
  if (which == JOB_OPEN) {
    smartcard_slot_reset();
    show_slot(card_present ? SMARTCARD_SLOT_PRESENT : SMARTCARD_SLOT_ABSENT);
    show_loading_spinner();
  } else if (which != JOB_WATCH) {
    smartcard_slot_notes(body);
    if (secret_menu)
      ui_menu_hide(secret_menu);
    chrome(true);
    if (title)
      lv_label_set_text(title, "Delete");
    lv_obj_clean(body);
    lv_obj_clear_flag(body, LV_OBJ_FLAG_HIDDEN);
    lv_obj_t *spinner = lv_spinner_create(body);
    theme_apply_spinner(spinner);
    lv_obj_set_size(spinner, 48, 48);
    lv_spinner_set_anim_params(spinner, 1000, 60);
    theme_create_label(body, status ? status : "", true);
  }
  done = false;
  if (!worker_task_start_io("seedkeeper", DELETE_STACK, worker, &done)) {
    smartcard_slot_notes(body);
    lv_obj_clean(body);
    theme_create_label(body, "Could not start the card task.", true);
    return;
  }
  running = true;
  poll_timer = lv_timer_create(poll_cb, 100, NULL);
}

static void clear_pin_ui(void) {
  ui_text_input_destroy(&pin_input);
  if (pin_host) {
    lv_obj_del(pin_host);
    pin_host = NULL;
  }
}

static void pin_submit(lv_timer_t *timer) {
  (void)timer;
  if (running || !pin_input.textarea)
    return;
  const char *text = lv_textarea_get_text(pin_input.textarea);
  size_t n = text ? strlen(text) : 0;
  if (n < SEEDKEEPER_PIN_MIN || n > SEEDKEEPER_PIN_MAX) {
    dialog_show_error_timeout("The PIN is 4 to 16 characters.", NULL, 0);
    return;
  }
  memcpy(pin, text, n);
  pin_len = n;
  clear_pin_ui();
  start_job(JOB_PIN, "Checking the PIN...");
}

static void pin_ready(lv_event_t *e) {
  (void)e;
  ui_oneshot_start(&defer, pin_submit, 0);
}

static void show_pin(void) {
  chrome(true);
  if (title)
    lv_label_set_text(title, "Card PIN");
  if (secret_menu)
    ui_menu_hide(secret_menu);
  lv_obj_add_flag(body, LV_OBJ_FLAG_HIDDEN);
  clear_pin_ui();
  pin_host = lv_obj_create(screen);
  lv_obj_remove_style_all(pin_host);
  lv_obj_set_size(pin_host, LV_PCT(100), LV_PCT(100));
  ui_text_input_create(&pin_input, pin_host, "4 to 16 characters", true,
                       pin_ready);
  lv_textarea_set_max_length(pin_input.textarea, SEEDKEEPER_PIN_MAX);
  if (back_btn)
    lv_obj_move_foreground(back_btn);
  if (title)
    lv_obj_move_foreground(title);
}

static const char *secret_name(int index, char *fallback, size_t cap) {
  if (index < 0 || index >= secret_count || !fallback || cap == 0)
    return "this secret";
  if (secrets[index].label[0])
    return secrets[index].label;
  snprintf(fallback, cap, "Secret %u", secrets[index].id);
  return fallback;
}

static void reset_now(lv_timer_t *timer) {
  (void)timer;
  if (running || reset_index < 0 || reset_index >= secret_count)
    return;
  start_job(JOB_RESET, "Deleting...");
}

static void confirm_cb(bool confirmed, void *user_data) {
  (void)user_data;
  if (!screen)
    return;
  if (!confirmed) {
    show_menu();
    return;
  }
  ui_oneshot_start(&defer, reset_now, 0);
}

static void pick_now(lv_timer_t *timer) {
  (void)timer;
  if (!secret_menu || running || !screen)
    return;
  int index = ui_menu_get_selected(secret_menu);
  if (index < 0 || index >= secret_count)
    return;
  reset_index = index;
  ui_menu_hide(secret_menu);
  char fallback[24];
  char msg[160];
  snprintf(msg, sizeof(msg),
           "Delete \"%s\" from the card?\nThis cannot be undone.",
           secret_name(index, fallback, sizeof(fallback)));
  dialog_show_danger_confirm(msg, confirm_cb, NULL, DIALOG_STYLE_OVERLAY);
}

static void pick_secret(void) { ui_oneshot_start(&defer, pick_now, 0); }

static void show_menu(void) {
  chrome(false);
  lv_obj_add_flag(body, LV_OBJ_FLAG_HIDDEN);
  if (secret_menu) {
    ui_menu_destroy(secret_menu);
    secret_menu = NULL;
  }
  secret_menu = ui_menu_create(
      screen, list_truncated ? "First 16 secrets" : "Secrets", return_callback);
  for (int i = 0; i < secret_count; i++) {
    char fallback[24];
    ui_menu_add_entry(secret_menu, secret_name(i, fallback, sizeof(fallback)),
                      pick_secret);
  }
  ui_menu_show(secret_menu);
}

static void list_now(lv_timer_t *timer) {
  (void)timer;
  show_menu();
}

static void back_cb(lv_event_t *e) {
  (void)e;
  if (return_callback)
    return_callback();
}

void smartcard_delete_create(lv_obj_t *parent, void (*return_cb)(void)) {
  session_cleanup_register(smartcard_delete_destroy);
  return_callback = return_cb;
  reset_index = -1;
  screen = theme_create_page_container(parent);
  back_btn = ui_create_back_button(screen, back_cb);
  title = theme_create_page_title(screen, "Delete");

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

  card_present = false;
  smartcard_slot_reset();
  start_job(JOB_OPEN, "Opening a secure session...");
}

void smartcard_delete_destroy(void) {
  session_cleanup_unregister(smartcard_delete_destroy);
  smartcard_pair_cancel();
  stop_watch();
  cancel_retry_timer();
  hide_loading_spinner();
  smartcard_slot_reset();
  ui_oneshot_cancel(&defer);
  if (running) {
    worker_task_wait();
    running = false;
  }
  if (poll_timer) {
    lv_timer_del(poll_timer);
    poll_timer = NULL;
  }
  if (secret_menu) {
    ui_menu_destroy(secret_menu);
    secret_menu = NULL;
  }
  clear_pin_ui();
  reader_down();
  if (screen) {
    lv_obj_del(screen);
    screen = NULL;
  }
  body = NULL;
  title = NULL;
  back_btn = NULL;
  return_callback = NULL;
  secure_memzero(pin, sizeof(pin));
  pin_len = 0;
  secure_memzero(secrets, sizeof(secrets));
  secret_count = 0;
  skipped_authentikey = 0;
  reset_index = -1;
}

#else

void smartcard_delete_create(lv_obj_t *parent, void (*return_cb)(void)) {
  (void)parent;
  (void)return_cb;
}

void smartcard_delete_destroy(void) {}

#endif
