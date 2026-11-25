/*
 * Load or save one Seedkeeper descriptor.
 *
 * The body is a 2-byte length and the UTF-8 text. It travels inside the
 * secure channel. A wrong PIN is sent once. The card's authentikey on the
 * export is not checked. The text is wiped when the page closes.
 */

#include "smartcard_descriptor.h"

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
#include <wally_crypto.h>

#define DESC_STACK (48 * 1024)
#define MAX_SECRETS 16
#define SECRET_MAX (SEEDKEEPER_DESCRIPTOR_MAX + 2)

enum { MODE_LOAD, MODE_SAVE };
enum { JOB_OPEN, JOB_PIN, JOB_LIST, JOB_EXPORT, JOB_SAVE };

static void (*return_callback)(void) = NULL;
static smartcard_descriptor_cb loaded_callback = NULL;
static lv_obj_t *screen = NULL;
static lv_obj_t *title = NULL;
static lv_obj_t *back_btn = NULL;
static lv_obj_t *body = NULL;
static lv_obj_t *pin_host = NULL;
static lv_obj_t *name_host = NULL;
static lv_timer_t *poll_timer = NULL;
static ui_oneshot_t defer;
static ui_text_input_t pin_input;
static ui_text_input_t name_input;
static ui_menu_t *secret_menu = NULL;
static volatile bool done;
static bool running;
static bool reader_up;
static int mode;
static int job;
static bool job_ok;
static bool ask_pin;
static char note[192];
static uint8_t pin[SEEDKEEPER_PIN_MAX];
static size_t pin_len;
static seedkeeper_header_t secrets[MAX_SECRETS];
static int secret_count;
static bool list_truncated;
static int export_index;
static char descriptor[SEEDKEEPER_DESCRIPTOR_MAX + 1];
static char saved_label[SEEDKEEPER_LABEL_MAX + 1];
static sec1210_err_t io_err;
static uint8_t sw1, sw2;

static void wipe_text(void) { secure_memzero(descriptor, sizeof(descriptor)); }

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

static void show_note(bool list_button) {
  chrome(true);
  if (title)
    lv_label_set_text(title, mode == MODE_SAVE ? "Save" : "Descriptor");
  if (secret_menu)
    ui_menu_hide(secret_menu);
  if (screen)
    lv_obj_clear_flag(screen, LV_OBJ_FLAG_HIDDEN);
  lv_obj_clean(body);
  lv_obj_clear_flag(body, LV_OBJ_FLAG_HIDDEN);
  const char *text = note[0] ? note : sec1210_err_str(io_err);
  if (!note[0] && io_err == SEC1210_OK)
    text = "The card did not accept the command.";
  lv_obj_t *label = theme_create_label(body, text, false);
  lv_obj_set_width(label, LV_PCT(100));
  lv_label_set_long_mode(label, LV_LABEL_LONG_WRAP);
  if (io_err != SEC1210_OK && sec1210_last_detail()[0]) {
    lv_obj_t *detail = theme_create_label(body, sec1210_last_detail(), false);
    lv_obj_set_width(detail, LV_PCT(100));
    lv_label_set_long_mode(detail, LV_LABEL_LONG_WRAP);
  }
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
  if (sw1 == 0x9C && sw2 == 0x31) {
    snprintf(note, sizeof(note), "The card refused a plaintext export.");
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

static bool send_apdu(const uint8_t *apdu, size_t apdu_len, uint8_t *resp,
                      size_t resp_cap, size_t *resp_len) {
  io_err = seedkeeper_session_transmit(apdu, apdu_len, resp, resp_cap, resp_len,
                                       &sw1, &sw2);
  return status_ok();
}

static void job_open(void) {
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
    if (seedkeeper_header_parse(resp, resp_len, &header) &&
        seedkeeper_can_descriptor(&header)) {
      if (secret_count < MAX_SECRETS)
        secrets[secret_count++] = header;
      else
        list_truncated = true;
    }
    secure_memzero(&header, sizeof(header));
    secure_memzero(resp, sizeof(resp));
    p2 = SEEDKEEPER_P2_NEXT;
  }
  snprintf(note, sizeof(note), "The card kept listing secrets.");
  io_err = SEC1210_ERR_PROTO;
}

static void job_export(void) {
  if (export_index < 0 || export_index >= secret_count) {
    io_err = SEC1210_ERR_ARG;
    return;
  }
  uint16_t sid = secrets[export_index].id;
  uint8_t apdu[16];
  uint8_t resp[SEC1210_MAX_APDU];
  uint8_t secret[SECRET_MAX];
  size_t secret_len = 0;
  size_t resp_len = 0;
  uint8_t fingerprint[4] = {0};
  bool have_header = false;
  bool last = false;

  size_t apdu_len =
      seedkeeper_apdu_export(sid, SEEDKEEPER_P2_INIT, apdu, sizeof(apdu));
  io_err = seedkeeper_session_transmit(apdu, apdu_len, resp, sizeof(resp),
                                       &resp_len, &sw1, &sw2);
  if (io_err != SEC1210_OK || !status_ok()) {
    if (io_err == SEC1210_OK)
      note_sw("Export failed");
    goto out;
  }
  seedkeeper_header_t header;
  if (!seedkeeper_header_parse(resp, resp_len, &header)) {
    snprintf(note, sizeof(note), "The card sent a bad secret header.");
    goto out;
  }
  memcpy(fingerprint, header.fingerprint, 4);
  have_header = true;
  secure_memzero(&header, sizeof(header));

  for (int i = 0; i < 64 && !last; i++) {
    apdu_len =
        seedkeeper_apdu_export(sid, SEEDKEEPER_P2_NEXT, apdu, sizeof(apdu));
    resp_len = 0;
    io_err = seedkeeper_session_transmit(apdu, apdu_len, resp, sizeof(resp),
                                         &resp_len, &sw1, &sw2);
    if (io_err != SEC1210_OK || !status_ok()) {
      if (io_err == SEC1210_OK)
        note_sw("Export failed");
      goto out;
    }
    const uint8_t *chunk = NULL;
    size_t chunk_len = 0;
    if (!seedkeeper_export_chunk(resp, resp_len, &chunk, &chunk_len, &last) ||
        secret_len + chunk_len > sizeof(secret)) {
      snprintf(note, sizeof(note), "The descriptor does not fit.");
      goto out;
    }
    if (chunk_len)
      memcpy(secret + secret_len, chunk, chunk_len);
    secret_len += chunk_len;
  }
  if (!last || !have_header) {
    snprintf(note, sizeof(note), "The export stopped early.");
    goto out;
  }

  uint8_t digest[32];
  if (wally_sha256(secret, secret_len, digest, sizeof(digest)) != WALLY_OK ||
      !seedkeeper_fingerprint_equal(fingerprint, digest)) {
    snprintf(note, sizeof(note),
             "Fingerprint does not match. The descriptor was not loaded.");
    secure_memzero(digest, sizeof(digest));
    goto out;
  }
  secure_memzero(digest, sizeof(digest));

  const uint8_t *text = NULL;
  size_t text_len = 0;
  if (seedkeeper_descriptor_decode(secret, secret_len, &text, &text_len) !=
          SEEDKEEPER_DECODE_OK ||
      text_len >= sizeof(descriptor)) {
    snprintf(note, sizeof(note), "The descriptor from the card is malformed.");
    goto out;
  }
  memcpy(descriptor, text, text_len);
  descriptor[text_len] = '\0';
  job_ok = true;

out:
  secure_memzero(secret, sizeof(secret));
  secure_memzero(resp, sizeof(resp));
  secure_memzero(apdu, sizeof(apdu));
  secure_memzero(fingerprint, sizeof(fingerprint));
}

static void job_save(void) {
  uint8_t secret[SECRET_MAX];
  uint8_t digest[32];
  uint8_t header[13 + SEEDKEEPER_LABEL_MAX];
  uint8_t apdu[8 + SEEDKEEPER_IMPORT_CHUNK];
  uint8_t resp[64];
  size_t secret_len = 0;
  size_t header_len = 0;
  size_t padded = 0;
  size_t apdu_len = 0;
  size_t resp_len = 0;
  size_t offset = 0;
  uint16_t sid = 0;
  uint8_t card_fp[4];

  secret_len = seedkeeper_secret_encode_descriptor(descriptor, secret,
                                                   sizeof(secret));
  if (!secret_len ||
      wally_sha256(secret, secret_len, digest, sizeof(digest)) != WALLY_OK) {
    snprintf(note, sizeof(note), "This descriptor cannot be stored.");
    goto out;
  }
  header_len = seedkeeper_import_header(
      SEEDKEEPER_TYPE_DESCRIPTOR, SEEDKEEPER_SUBTYPE_DEFAULT,
      SEEDKEEPER_EXPORT_ALLOWED, saved_label, header, sizeof(header));
  padded = seedkeeper_padded_secret_size(secret_len);
  if (!header_len || !padded || padded > 0xFFFF) {
    snprintf(note, sizeof(note), "This descriptor cannot be stored.");
    goto out;
  }
  apdu_len = seedkeeper_apdu_import_init(header, header_len, (uint16_t)padded,
                                         apdu, sizeof(apdu));
  if (!apdu_len || !send_apdu(apdu, apdu_len, resp, sizeof(resp), &resp_len)) {
    if (io_err == SEC1210_OK && !note[0])
      note_sw("Save failed");
    goto out;
  }

  while (secret_len - offset > SEEDKEEPER_IMPORT_CHUNK) {
    apdu_len = seedkeeper_apdu_import_data(SEEDKEEPER_P2_NEXT, secret + offset,
                                           SEEDKEEPER_IMPORT_CHUNK, apdu,
                                           sizeof(apdu));
    if (!apdu_len ||
        !send_apdu(apdu, apdu_len, resp, sizeof(resp), &resp_len)) {
      if (io_err == SEC1210_OK && !note[0])
        note_sw("Save failed");
      goto out;
    }
    offset += SEEDKEEPER_IMPORT_CHUNK;
  }
  apdu_len = seedkeeper_apdu_import_data(SEEDKEEPER_P2_FINAL, secret + offset,
                                         secret_len - offset, apdu,
                                         sizeof(apdu));
  if (!apdu_len || !send_apdu(apdu, apdu_len, resp, sizeof(resp), &resp_len)) {
    if (io_err == SEC1210_OK && !note[0])
      note_sw("Save failed");
    goto out;
  }
  if (!seedkeeper_import_result(resp, resp_len, &sid, card_fp)) {
    snprintf(note, sizeof(note), "The card reply was incomplete.");
    goto out;
  }
  if (!seedkeeper_fingerprint_equal(card_fp, digest)) {
    apdu_len = seedkeeper_apdu_reset(sid, apdu, sizeof(apdu));
    bool removed =
        apdu_len && send_apdu(apdu, apdu_len, resp, sizeof(resp), &resp_len);
    if (removed)
      snprintf(note, sizeof(note),
               "The card stored a different fingerprint, so that secret was "
               "removed.");
    else
      snprintf(note, sizeof(note),
               "The card stored a different fingerprint (id %u). It is still "
               "on the card.",
               (unsigned)sid);
    goto out;
  }

  snprintf(note, sizeof(note), "Saved as %s.", saved_label);
  job_ok = true;

out:
  secure_memzero(secret, sizeof(secret));
  secure_memzero(digest, sizeof(digest));
  secure_memzero(header, sizeof(header));
  secure_memzero(apdu, sizeof(apdu));
  secure_memzero(resp, sizeof(resp));
  secure_memzero(card_fp, sizeof(card_fp));
}

static void worker(void) {
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
  else if (job == JOB_EXPORT)
    job_export();
  else
    job_save();
}

static void show_pin(void);
static void clear_pin_ui(void);
static void start_job(int which, const char *status);

static void show_pin_after_error(void) {
  if (screen)
    show_pin();
}

static void after_open(void) {
  if (!job_ok) {
    show_note(false);
    reader_down();
    return;
  }
  show_pin();
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
  if (mode == MODE_SAVE)
    start_job(JOB_SAVE, "Saving the descriptor...");
  else
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
    snprintf(note, sizeof(note),
             "No descriptor on the card can be exported in the clear.");
    show_note(false);
    return;
  }
  show_menu();
}

static void after_export(void) {
  if (ask_pin) {
    wipe_text();
    clear_pin_ui();
    dialog_show_error_timeout(note, show_pin_after_error, 0);
    return;
  }
  if (!job_ok) {
    wipe_text();
    bool keep = io_err == SEC1210_OK && seedkeeper_session_is_open();
    show_note(keep);
    if (!keep)
      reader_down();
    return;
  }
  smartcard_descriptor_cb loaded = loaded_callback;
  if (screen)
    lv_obj_add_flag(screen, LV_OBJ_FLAG_HIDDEN);
  if (loaded)
    loaded(descriptor);
}

static void after_save(void) {
  if (ask_pin) {
    clear_pin_ui();
    dialog_show_error_timeout(note, show_pin_after_error, 0);
    return;
  }
  show_note(false);
  if (!job_ok && io_err != SEC1210_OK)
    reader_down();
}

static void poll_cb(lv_timer_t *timer) {
  (void)timer;
  if (!done)
    return;
  worker_task_wait();
  running = false;
  lv_timer_del(poll_timer);
  poll_timer = NULL;
  if (job == JOB_OPEN)
    after_open();
  else if (job == JOB_PIN)
    after_pin();
  else if (job == JOB_LIST)
    after_list();
  else if (job == JOB_EXPORT)
    after_export();
  else
    after_save();
}

static void start_job(int which, const char *status) {
  if (running || !body)
    return;
  job = which;
  if (secret_menu)
    ui_menu_hide(secret_menu);
  chrome(true);
  if (title)
    lv_label_set_text(title, mode == MODE_SAVE ? "Save" : "Descriptor");
  if (screen)
    lv_obj_clear_flag(screen, LV_OBJ_FLAG_HIDDEN);
  lv_obj_clean(body);
  lv_obj_clear_flag(body, LV_OBJ_FLAG_HIDDEN);
  theme_create_label(body, status, true);
  done = false;
  if (!worker_task_start_io("seedkeeper", DESC_STACK, worker, &done)) {
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

static void clear_name_ui(void) {
  ui_text_input_destroy(&name_input);
  if (name_host) {
    lv_obj_del(name_host);
    name_host = NULL;
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
  if (screen)
    lv_obj_clear_flag(screen, LV_OBJ_FLAG_HIDDEN);
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

static void pick_now(lv_timer_t *timer) {
  (void)timer;
  if (!secret_menu || running)
    return;
  int index = ui_menu_get_selected(secret_menu);
  if (index < 0 || index >= secret_count)
    return;
  export_index = index;
  ui_menu_hide(secret_menu);
  start_job(JOB_EXPORT, "Reading the descriptor...");
}

static void pick_secret(void) { ui_oneshot_start(&defer, pick_now, 0); }

static void show_menu(void) {
  chrome(false);
  if (screen)
    lv_obj_clear_flag(screen, LV_OBJ_FLAG_HIDDEN);
  lv_obj_add_flag(body, LV_OBJ_FLAG_HIDDEN);
  if (secret_menu) {
    ui_menu_destroy(secret_menu);
    secret_menu = NULL;
  }
  secret_menu = ui_menu_create(
      screen, list_truncated ? "First 16 descriptors" : "Descriptors",
      return_callback);
  for (int i = 0; i < secret_count; i++) {
    char fallback[24];
    const char *name = secrets[i].label;
    if (!name[0]) {
      snprintf(fallback, sizeof(fallback), "Descriptor %u", secrets[i].id);
      name = fallback;
    }
    ui_menu_add_entry(secret_menu, name, pick_secret);
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

static void build_screen(lv_obj_t *parent, const char *page_title) {
  screen = theme_create_page_container(parent);
  back_btn = ui_create_back_button(screen, back_cb);
  title = theme_create_page_title(screen, page_title);

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
}

static void copy_label(const char *label) {
  const char *src = (label && label[0]) ? label : "Kern";
  size_t n = strlen(src);
  if (n > SEEDKEEPER_LABEL_MAX)
    n = SEEDKEEPER_LABEL_MAX;
  memcpy(saved_label, src, n);
  saved_label[n] = '\0';
}

static void name_error_done(void) {
  if (name_input.keyboard)
    lv_obj_clear_flag(name_input.keyboard, LV_OBJ_FLAG_HIDDEN);
}

static void name_reject(const char *message) {
  if (name_input.keyboard)
    lv_obj_add_flag(name_input.keyboard, LV_OBJ_FLAG_HIDDEN);
  dialog_show_error_timeout(message, name_error_done, 0);
}

static void name_submit(lv_timer_t *timer) {
  (void)timer;
  if (running || !name_input.textarea)
    return;
  const char *text = lv_textarea_get_text(name_input.textarea);
  size_t n = text ? strlen(text) : 0;
  if (n == 0) {
    name_reject("Please enter a name.");
    return;
  }
  if (n > SEEDKEEPER_LABEL_MAX) {
    name_reject("The name is too long for the card.");
    return;
  }
  memcpy(saved_label, text, n);
  saved_label[n] = '\0';
  clear_name_ui();
  start_job(JOB_OPEN, "Opening a secure session...");
}

static void name_ready(lv_event_t *e) {
  (void)e;
  ui_oneshot_start(&defer, name_submit, 0);
}

static void show_name(void) {
  chrome(true);
  if (title)
    lv_label_set_text(title, "Name");
  lv_obj_add_flag(body, LV_OBJ_FLAG_HIDDEN);
  clear_name_ui();
  name_host = lv_obj_create(screen);
  lv_obj_remove_style_all(name_host);
  lv_obj_set_size(name_host, LV_PCT(100), LV_PCT(100));
  ui_text_input_create(&name_input, name_host, "Secret name", false, name_ready);
  lv_textarea_set_max_length(name_input.textarea, SEEDKEEPER_LABEL_MAX);
  if (saved_label[0])
    lv_textarea_set_text(name_input.textarea, saved_label);
  if (back_btn)
    lv_obj_move_foreground(back_btn);
  if (title)
    lv_obj_move_foreground(title);
}

void smartcard_descriptor_load_create(lv_obj_t *parent, void (*return_cb)(void),
                                      smartcard_descriptor_cb loaded_cb) {
  session_cleanup_register(smartcard_descriptor_load_destroy);
  return_callback = return_cb;
  loaded_callback = loaded_cb;
  mode = MODE_LOAD;
  build_screen(parent, "Descriptor");
  start_job(JOB_OPEN, "Opening a secure session...");
}

void smartcard_descriptor_load_resume(void) {
  if (!screen || mode != MODE_LOAD)
    return;
  if (secret_count > 0)
    show_menu();
  else
    show_note(false);
}

void smartcard_descriptor_save_create(lv_obj_t *parent, void (*return_cb)(void),
                                      const char *text, const char *label) {
  session_cleanup_register(smartcard_descriptor_load_destroy);
  return_callback = return_cb;
  loaded_callback = NULL;
  mode = MODE_SAVE;
  build_screen(parent, "Save");
  copy_label(label);
  size_t n = text ? strlen(text) : 0;
  if (n == 0 || n > SEEDKEEPER_DESCRIPTOR_MAX) {
    snprintf(note, sizeof(note),
             n == 0 ? "There is no descriptor to save."
                    : "The descriptor is too long for the card.");
    io_err = SEC1210_OK;
    show_note(false);
    return;
  }
  memcpy(descriptor, text, n);
  descriptor[n] = '\0';
  show_name();
}

void smartcard_descriptor_load_destroy(void) {
  session_cleanup_unregister(smartcard_descriptor_load_destroy);
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
  clear_name_ui();
  reader_down();
  if (screen) {
    lv_obj_del(screen);
    screen = NULL;
  }
  body = NULL;
  title = NULL;
  back_btn = NULL;
  return_callback = NULL;
  loaded_callback = NULL;
  secure_memzero(pin, sizeof(pin));
  pin_len = 0;
  secure_memzero(secrets, sizeof(secrets));
  secret_count = 0;
  secure_memzero(saved_label, sizeof(saved_label));
  wipe_text();
}

void smartcard_descriptor_save_destroy(void) {
  smartcard_descriptor_load_destroy();
}

#else

void smartcard_descriptor_load_create(lv_obj_t *parent, void (*return_cb)(void),
                                      smartcard_descriptor_cb loaded_cb) {
  (void)parent;
  (void)return_cb;
  (void)loaded_cb;
}

void smartcard_descriptor_load_resume(void) {}
void smartcard_descriptor_load_destroy(void) {}

void smartcard_descriptor_save_create(lv_obj_t *parent, void (*return_cb)(void),
                                      const char *text, const char *label) {
  (void)parent;
  (void)return_cb;
  (void)text;
  (void)label;
}

void smartcard_descriptor_save_destroy(void) {}

#endif
