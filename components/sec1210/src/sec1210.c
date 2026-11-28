#include "sec1210.h"

#include "sec1210_frame.h"

#include "driver/gpio.h"
#include "driver/uart.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include <stdio.h>
#include <string.h>

static const char *TAG = "sec1210";

/* Hat TX -> Pico GPIO22 (UART RX). Hat RX <- Pico GPIO20 (UART TX). */
#define SEC1210_UART UART_NUM_1
#define SEC1210_TX GPIO_NUM_20
#define SEC1210_RX GPIO_NUM_22
#define SEC1210_BAUD 115200
#define SEC1210_EXCHANGE_MS 3000
/* Key generation on the card is slow. A block transfer waits this long, and
 * either a one-byte wait (0x80-0xFF) or a CCID time-extension restarts that
 * wait, up to the cap. */
#define SEC1210_XFR_MS 10000
#define SEC1210_EXCHANGE_CAP_MS 30000
#define SEC1210_ATTEMPTS 3
#define SEC1210_T1_TURNS 32

static bool s_open;
static uint8_t s_seq;
static char s_detail[80];
static bool s_t1;
static uint8_t s_ns;
static uint8_t s_nr;
static bool s_ifsd;

static void t1_reset(void) {
  s_t1 = false;
  s_ns = 0;
  s_nr = 0;
  s_ifsd = false;
}

static void wipe(void *ptr, size_t len) {
  volatile uint8_t *p = ptr;
  if (!p)
    return;
  while (len--)
    *p++ = 0;
}

const char *sec1210_err_str(sec1210_err_t err) {
  switch (err) {
  case SEC1210_OK:
    return "ok";
  case SEC1210_ERR_ARG:
    return "bad argument";
  case SEC1210_ERR_IO:
    return "uart error";
  case SEC1210_ERR_NAK:
    return "reader rejected the frame";
  case SEC1210_ERR_TIMEOUT:
    return "reader did not answer";
  case SEC1210_ERR_PROTO:
    return "bad reader frame";
  case SEC1210_ERR_CARD:
    return "card error";
  }
  return "unknown";
}

const char *sec1210_last_detail(void) { return s_detail; }

static void note_frame(const uint8_t *msg, size_t len) {
  size_t show = len < 12 ? len : 12;
  size_t used = 0;
  s_detail[0] = '\0';
  for (size_t i = 0; i < show && used + 3 < sizeof(s_detail); i++) {
    int n = snprintf(s_detail + used, sizeof(s_detail) - used, "%02X", msg[i]);
    if (n < 0)
      return;
    used += (size_t)n;
  }
}

sec1210_err_t sec1210_init(void) {
  if (s_open)
    return SEC1210_OK;

  const uart_config_t cfg = {
      .baud_rate = SEC1210_BAUD,
      .data_bits = UART_DATA_8_BITS,
      .parity = UART_PARITY_DISABLE,
      .stop_bits = UART_STOP_BITS_1,
      .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
      .source_clk = UART_SCLK_DEFAULT,
  };
  esp_err_t err = uart_driver_install(SEC1210_UART, SEC1210_MAX_FRAME, 0, 0,
                                      NULL, 0);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "uart install failed: %s", esp_err_to_name(err));
    return SEC1210_ERR_IO;
  }
  err = uart_param_config(SEC1210_UART, &cfg);
  if (err == ESP_OK)
    err = uart_set_pin(SEC1210_UART, SEC1210_TX, SEC1210_RX, UART_PIN_NO_CHANGE,
                       UART_PIN_NO_CHANGE);
  if (err != ESP_OK) {
    uart_driver_delete(SEC1210_UART);
    ESP_LOGE(TAG, "uart config failed: %s", esp_err_to_name(err));
    return SEC1210_ERR_IO;
  }
  gpio_set_pull_mode(SEC1210_RX, GPIO_PULLUP_ONLY);
  s_seq = 0;
  t1_reset();
  s_open = true;
  return SEC1210_OK;
}

void sec1210_deinit(void) {
  if (!s_open)
    return;
  uart_driver_delete(SEC1210_UART);
  t1_reset();
  s_open = false;
}

static sec1210_err_t transact(const uint8_t *ccid, size_t ccid_len,
                              uint8_t expect, uint8_t *resp, size_t resp_cap,
                              size_t *resp_len, uint32_t timeout_ms) {
  uint8_t frame[SEC1210_MAX_FRAME];
  size_t frame_len = sec1210_frame_encode(ccid, ccid_len, frame, sizeof(frame));
  if (frame_len == 0) {
    return SEC1210_ERR_ARG;
  }

  s_detail[0] = '\0';
  sec1210_err_t result = SEC1210_ERR_TIMEOUT;
  for (int attempt = 0; attempt < SEC1210_ATTEMPTS; attempt++) {
    result = SEC1210_ERR_TIMEOUT;
    uart_flush_input(SEC1210_UART);
    int written = uart_write_bytes(SEC1210_UART, frame, frame_len);
    if (written != (int)frame_len) {
      result = SEC1210_ERR_IO;
      break;
    }
    if (uart_wait_tx_done(SEC1210_UART, pdMS_TO_TICKS(200)) != ESP_OK) {
      result = SEC1210_ERR_IO;
      break;
    }

    sec1210_parser_t parser;
    sec1210_parser_reset(&parser);
    TickType_t start = xTaskGetTickCount();
    TickType_t deadline = start + pdMS_TO_TICKS(timeout_ms);
    TickType_t latest = start + pdMS_TO_TICKS(SEC1210_EXCHANGE_CAP_MS);
    bool finished = false;
    bool card_busy = false;
    while ((int32_t)(deadline - xTaskGetTickCount()) > 0) {
      uint8_t byte = 0;
      int n = uart_read_bytes(SEC1210_UART, &byte, 1, pdMS_TO_TICKS(50));
      if (n <= 0)
        continue;

      sec1210_feed_t feed = sec1210_parser_byte(&parser, byte);
      /* One-byte wait: the reader accepted the command and the card is still
       * computing. Restart the window. Do not send the command again. */
      if (feed == SEC1210_FEED_WAIT) {
        card_busy = true;
        TickType_t next = xTaskGetTickCount() + pdMS_TO_TICKS(timeout_ms);
        deadline = ((int32_t)(next - latest) > 0) ? latest : next;
        continue;
      }
      if (feed == SEC1210_FEED_NEED_MORE || feed == SEC1210_FEED_SLOT)
        continue;
      if (feed == SEC1210_FEED_NAK) {
        result = SEC1210_ERR_NAK;
        finished = false;
        break;
      }
      /* A stray byte or a bad LRC must not drop the real answer that follows. */
      if (feed != SEC1210_FEED_FRAME) {
        result = SEC1210_ERR_PROTO;
        continue;
      }
      /* GemPC-style readers echo the command before the answer. */
      if (parser.have == ccid_len && memcmp(parser.ccid, ccid, ccid_len) == 0) {
        card_busy = true;
        continue;
      }
      if (parser.have < SEC1210_CCID_HEADER || parser.have > resp_cap) {
        result = SEC1210_ERR_PROTO;
        continue;
      }
      note_frame(parser.ccid, parser.have);
      /* Time extension: the card is still working. Grant another window. */
      if ((parser.ccid[7] & 0xC0) == 0x80) {
        card_busy = true;
        uint32_t mul = parser.ccid[8];
        if (mul == 0 || mul > 30)
          mul = 1;
        uint32_t extra_ms = mul * 1000;
        if (extra_ms < timeout_ms)
          extra_ms = timeout_ms;
        TickType_t next = xTaskGetTickCount() + pdMS_TO_TICKS(extra_ms);
        deadline = ((int32_t)(next - latest) > 0) ? latest : next;
        continue;
      }
      if (expect != 0 && parser.ccid[0] != expect &&
          (parser.ccid[7] & 0xC0) != 0x40)
        continue;
      memcpy(resp, parser.ccid, parser.have);
      *resp_len = parser.have;
      result = SEC1210_OK;
      finished = true;
      break;
    }
    wipe(&parser, sizeof(parser));
    if (finished)
      break;
    /* NAK, or a silent timeout: the reader never started the card, so the
     * same command can be sent again. Once the card is busy, resending would
     * collide with the answer that is still coming. */
    if (result == SEC1210_ERR_NAK)
      continue;
    if (card_busy || result != SEC1210_ERR_TIMEOUT)
      break;
  }

  wipe(frame, sizeof(frame));
  return result;
}

static uint32_t ccid_length(const uint8_t *msg) {
  return (uint32_t)msg[1] | ((uint32_t)msg[2] << 8) | ((uint32_t)msg[3] << 16) |
         ((uint32_t)msg[4] << 24);
}

static sec1210_err_t exchange(const uint8_t *cmd, size_t cmd_len, uint8_t expect,
                              uint8_t *resp, size_t *resp_len,
                              uint32_t timeout_ms) {
  if (!s_open)
    return SEC1210_ERR_IO;
  uint8_t raw[SEC1210_MAX_CCID];
  size_t raw_len = 0;
  sec1210_err_t err =
      transact(cmd, cmd_len, expect, raw, sizeof(raw), &raw_len, timeout_ms);
  s_seq++;
  if (err != SEC1210_OK) {
    wipe(raw, sizeof(raw));
    return err;
  }
  if (raw_len < SEC1210_CCID_HEADER || (raw[7] & 0xC0) == 0x40) {
    wipe(raw, sizeof(raw));
    return (raw_len >= SEC1210_CCID_HEADER && (raw[7] & 0xC0) == 0x40)
               ? SEC1210_ERR_CARD
               : SEC1210_ERR_PROTO;
  }
  if (expect != 0 && raw[0] != expect) {
    wipe(raw, sizeof(raw));
    return SEC1210_ERR_PROTO;
  }
  uint32_t dlen = ccid_length(raw);
  if (dlen > SEC1210_MAX_PAYLOAD || SEC1210_CCID_HEADER + dlen != raw_len) {
    wipe(raw, sizeof(raw));
    return SEC1210_ERR_PROTO;
  }
  if (resp && resp_len) {
    if (*resp_len < dlen) {
      wipe(raw, sizeof(raw));
      return SEC1210_ERR_ARG;
    }
    memcpy(resp, raw + SEC1210_CCID_HEADER, dlen);
    *resp_len = dlen;
  }
  wipe(raw, sizeof(raw));
  return SEC1210_OK;
}

sec1210_err_t sec1210_slot_status(sec1210_card_t *card) {
  if (!card)
    return SEC1210_ERR_ARG;
  uint8_t cmd[SEC1210_CCID_HEADER];
  size_t cmd_len = sec1210_ccid_slot_status(s_seq, cmd, sizeof(cmd));
  uint8_t raw[SEC1210_MAX_CCID];
  size_t raw_len = 0;
  if (!s_open)
    return SEC1210_ERR_IO;
  uint8_t seq = cmd[6];
  sec1210_err_t err =
      transact(cmd, cmd_len, SEC1210_CCID_SLOT, raw, sizeof(raw), &raw_len,
               SEC1210_EXCHANGE_MS);
  s_seq++;
  if (err != SEC1210_OK) {
    wipe(raw, sizeof(raw));
    return err;
  }
  if (raw_len < SEC1210_CCID_HEADER || raw[0] != SEC1210_CCID_SLOT ||
      raw[6] != seq) {
    wipe(raw, sizeof(raw));
    return SEC1210_ERR_PROTO;
  }
  if ((raw[7] & 0xC0) == 0x40) {
    wipe(raw, sizeof(raw));
    return SEC1210_ERR_CARD;
  }
  switch (raw[7] & 0x03) {
  case 0:
    *card = SEC1210_CARD_ACTIVE;
    break;
  case 1:
    *card = SEC1210_CARD_INACTIVE;
    break;
  default:
    *card = SEC1210_CARD_ABSENT;
    break;
  }
  wipe(raw, sizeof(raw));
  return SEC1210_OK;
}

sec1210_err_t sec1210_power_on(uint8_t *atr, size_t atr_cap, size_t *atr_len) {
  if (!atr || !atr_len)
    return SEC1210_ERR_ARG;
  /* This reader does not advertise automatic voltage selection. pcscd
   * starts at 5 V and steps down when the card rejects it. */
  static const uint8_t voltages[] = {1, 2, 3};
  sec1210_power_off();
  sec1210_err_t err = SEC1210_ERR_CARD;
  for (size_t i = 0; i < sizeof(voltages); i++) {
    uint8_t cmd[SEC1210_CCID_HEADER];
    size_t cmd_len =
        sec1210_ccid_power_on(s_seq, voltages[i], cmd, sizeof(cmd));
    *atr_len = atr_cap;
    err = exchange(cmd, cmd_len, SEC1210_CCID_DATA, atr, atr_len,
                   SEC1210_EXCHANGE_MS);
    if (err == SEC1210_OK) {
      /* The SEC1210 exchanges TPDUs. This card's ATR offers T=1, so the
       * APDU has to ride in a T=1 block. */
      s_t1 = sec1210_atr_is_t1(atr, *atr_len);
      s_ns = 0;
      s_nr = 0;
      s_ifsd = false;
      return SEC1210_OK;
    }
    if (err != SEC1210_ERR_CARD)
      break;
  }
  *atr_len = 0;
  return err;
}

sec1210_err_t sec1210_power_off(void) {
  uint8_t cmd[SEC1210_CCID_HEADER];
  size_t cmd_len = sec1210_ccid_power_off(s_seq, cmd, sizeof(cmd));
  sec1210_err_t err = exchange(cmd, cmd_len, SEC1210_CCID_SLOT, NULL, NULL,
                               SEC1210_EXCHANGE_MS);
  t1_reset();
  return err;
}

static sec1210_err_t xfr_block(const uint8_t *data, size_t data_len,
                               uint8_t *resp, size_t resp_cap, size_t *resp_len) {
  uint8_t cmd[SEC1210_MAX_CCID];
  size_t cmd_len = sec1210_ccid_xfr(s_seq, data, data_len, cmd, sizeof(cmd));
  if (cmd_len == 0)
    return SEC1210_ERR_ARG;
  *resp_len = resp_cap;
  sec1210_err_t err = exchange(cmd, cmd_len, SEC1210_CCID_DATA, resp, resp_len,
                               SEC1210_XFR_MS);
  wipe(cmd, sizeof(cmd));
  return err;
}

static sec1210_err_t t1_send(uint8_t pcb, const uint8_t *inf, size_t inf_len,
                             uint8_t *reply_pcb, uint8_t *reply_inf,
                             size_t reply_cap, size_t *reply_len) {
  uint8_t block[4 + 254];
  size_t n = sec1210_t1_build(pcb, inf, inf_len, block, sizeof(block));
  if (n == 0)
    return SEC1210_ERR_ARG;
  uint8_t raw[4 + 254];
  size_t raw_len = 0;
  sec1210_err_t err = xfr_block(block, n, raw, sizeof(raw), &raw_len);
  wipe(block, sizeof(block));
  if (err != SEC1210_OK) {
    wipe(raw, sizeof(raw));
    return err;
  }
  if (!sec1210_t1_check(raw, raw_len, reply_pcb, reply_inf, reply_cap,
                        reply_len)) {
    note_frame(raw, raw_len);
    wipe(raw, sizeof(raw));
    return SEC1210_ERR_PROTO;
  }
  wipe(raw, sizeof(raw));
  return SEC1210_OK;
}

static sec1210_err_t t1_ifsd(void) {
  if (s_ifsd)
    return SEC1210_OK;
  uint8_t ifsd = 0xFE;
  uint8_t pcb = 0;
  uint8_t inf[8];
  size_t inf_len = 0;
  sec1210_err_t err = t1_send(0xC1, &ifsd, 1, &pcb, inf, sizeof(inf), &inf_len);
  wipe(inf, sizeof(inf));
  if (err != SEC1210_OK)
    return err;
  if (pcb != 0xE1)
    return SEC1210_ERR_PROTO;
  s_ifsd = true;
  return SEC1210_OK;
}

static sec1210_err_t finish_apdu(uint8_t *resp, size_t resp_cap, size_t got,
                                 size_t *resp_len, uint8_t *sw1, uint8_t *sw2) {
  if (got < 2 || got - 2 > resp_cap)
    return got < 2 ? SEC1210_ERR_PROTO : SEC1210_ERR_ARG;
  *resp_len = got - 2;
  *sw1 = resp[got - 2];
  *sw2 = resp[got - 1];
  return SEC1210_OK;
}

static sec1210_err_t t1_apdu(const uint8_t *apdu, size_t apdu_len, uint8_t *resp,
                             size_t resp_cap, size_t *resp_len, uint8_t *sw1,
                             uint8_t *sw2) {
  if (apdu_len > 254)
    return SEC1210_ERR_ARG;
  sec1210_err_t err = t1_ifsd();
  if (err != SEC1210_OK)
    return err;

  uint8_t tx_pcb = s_ns ? 0x40 : 0x00;
  const uint8_t *tx = apdu;
  size_t tx_len = apdu_len;
  bool acked = false;
  size_t got = 0;
  uint8_t held[8];
  size_t held_len = 0;

  for (int turn = 0; turn < SEC1210_T1_TURNS; turn++) {
    uint8_t pcb = 0;
    uint8_t inf[254];
    size_t inf_len = 0;
    err = t1_send(tx_pcb, tx, tx_len, &pcb, inf, sizeof(inf), &inf_len);
    if (err != SEC1210_OK) {
      wipe(inf, sizeof(inf));
      return err;
    }
    if ((pcb & 0xC0) == 0xC0) {
      if ((pcb & 0x20) == 0 && (pcb & 0x1F) == 0x03 && inf_len <= sizeof(held)) {
        memcpy(held, inf, inf_len);
        held_len = inf_len;
        tx_pcb = 0xE3;
        tx = held;
        tx_len = held_len;
        wipe(inf, sizeof(inf));
        continue;
      }
      wipe(inf, sizeof(inf));
      return SEC1210_ERR_PROTO;
    }
    if ((pcb & 0xC0) == 0x80) {
      bool resend_apdu = false;
      wipe(inf, sizeof(inf));
      if (!sec1210_t1_on_rblock(pcb, acked, s_ns, s_nr, &tx_pcb, &resend_apdu))
        return SEC1210_ERR_PROTO;
      tx = resend_apdu ? apdu : NULL;
      tx_len = resend_apdu ? apdu_len : 0;
      continue;
    }
    if (pcb & 0x80) {
      wipe(inf, sizeof(inf));
      return SEC1210_ERR_PROTO;
    }
    if (((pcb & 0x40) ? 1 : 0) != s_nr) {
      wipe(inf, sizeof(inf));
      return SEC1210_ERR_PROTO;
    }
    if (!acked) {
      s_ns ^= 1;
      acked = true;
    }
    if (got + inf_len > resp_cap) {
      wipe(inf, sizeof(inf));
      return SEC1210_ERR_ARG;
    }
    memcpy(resp + got, inf, inf_len);
    got += inf_len;
    s_nr ^= 1;
    wipe(inf, sizeof(inf));
    if (pcb & 0x20) {
      tx_pcb = 0x80 | (s_nr ? 0x10 : 0x00);
      tx = NULL;
      tx_len = 0;
      continue;
    }
    return finish_apdu(resp, resp_cap, got, resp_len, sw1, sw2);
  }
  return SEC1210_ERR_PROTO;
}

sec1210_err_t sec1210_transmit(const uint8_t *apdu, size_t apdu_len,
                               uint8_t *resp, size_t resp_cap, size_t *resp_len,
                               uint8_t *sw1, uint8_t *sw2) {
  if (!apdu || apdu_len == 0 || !resp || !resp_len || !sw1 || !sw2)
    return SEC1210_ERR_ARG;
  if (s_t1)
    return t1_apdu(apdu, apdu_len, resp, resp_cap, resp_len, sw1, sw2);

  uint8_t raw[SEC1210_MAX_PAYLOAD];
  size_t raw_len = 0;
  sec1210_err_t err = xfr_block(apdu, apdu_len, raw, sizeof(raw), &raw_len);
  if (err != SEC1210_OK) {
    wipe(raw, sizeof(raw));
    return err;
  }
  err = finish_apdu(raw, sizeof(raw), raw_len, resp_len, sw1, sw2);
  if (err == SEC1210_OK) {
    if (*resp_len > resp_cap) {
      wipe(raw, sizeof(raw));
      return SEC1210_ERR_ARG;
    }
    memcpy(resp, raw, *resp_len);
  }
  wipe(raw, sizeof(raw));
  return err;
}
