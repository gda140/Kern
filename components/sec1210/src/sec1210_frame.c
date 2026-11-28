#include "sec1210_frame.h"

#include <string.h>

void sec1210_parser_reset(sec1210_parser_t *parser) {
  if (!parser)
    return;
  memset(parser, 0, sizeof(*parser));
}

sec1210_feed_t sec1210_parser_byte(sec1210_parser_t *parser, uint8_t byte) {
  if (!parser)
    return SEC1210_FEED_ERROR;

  switch (parser->state) {
  case 0:
    if (byte == SEC1210_NOTIFY) {
      parser->state = 10;
      return SEC1210_FEED_NEED_MORE;
    }
    if (byte >= 0x80)
      return SEC1210_FEED_WAIT;
    if (byte == SEC1210_SYNC) {
      parser->lrc = byte;
      parser->state = 1;
      return SEC1210_FEED_NEED_MORE;
    }
    parser->state = 0;
    return SEC1210_FEED_ERROR;

  case 10:
    parser->slot = byte;
    parser->state = 0;
    return SEC1210_FEED_SLOT;

  case 1:
    parser->lrc ^= byte;
    if (byte == SEC1210_NAK) {
      parser->state = 2;
      return SEC1210_FEED_NEED_MORE;
    }
    if (byte == SEC1210_ACK) {
      parser->have = 0;
      parser->state = 3;
      return SEC1210_FEED_NEED_MORE;
    }
    parser->state = 0;
    return SEC1210_FEED_ERROR;

  case 2:
    if (byte != parser->lrc) {
      parser->state = 0;
      return SEC1210_FEED_ERROR;
    }
    parser->state = 0;
    return SEC1210_FEED_NAK;

  case 3:
  case 4:
    if (parser->have >= SEC1210_MAX_CCID) {
      parser->state = 0;
      return SEC1210_FEED_ERROR;
    }
    parser->ccid[parser->have++] = byte;
    parser->lrc ^= byte;
    if (parser->state == 3 && parser->have == SEC1210_CCID_HEADER) {
      uint32_t dlen = (uint32_t)parser->ccid[1] |
                      ((uint32_t)parser->ccid[2] << 8) |
                      ((uint32_t)parser->ccid[3] << 16) |
                      ((uint32_t)parser->ccid[4] << 24);
      if (dlen > SEC1210_MAX_PAYLOAD) {
        parser->state = 0;
        return SEC1210_FEED_ERROR;
      }
      parser->need = SEC1210_CCID_HEADER + (size_t)dlen;
      parser->state = dlen == 0 ? 5 : 4;
      return SEC1210_FEED_NEED_MORE;
    }
    if (parser->state == 4 && parser->have == parser->need)
      parser->state = 5;
    return SEC1210_FEED_NEED_MORE;

  case 5:
    if (byte != parser->lrc) {
      parser->state = 0;
      return SEC1210_FEED_ERROR;
    }
    parser->state = 0;
    return SEC1210_FEED_FRAME;

  default:
    parser->state = 0;
    return SEC1210_FEED_ERROR;
  }
}

size_t sec1210_frame_encode(const uint8_t *ccid, size_t ccid_len, uint8_t *out,
                            size_t out_cap) {
  if (!ccid || !out || ccid_len < SEC1210_CCID_HEADER ||
      ccid_len > SEC1210_MAX_CCID || out_cap < ccid_len + 3)
    return 0;

  out[0] = SEC1210_SYNC;
  out[1] = SEC1210_ACK;
  memcpy(out + 2, ccid, ccid_len);
  uint8_t lrc = 0;
  for (size_t i = 0; i < ccid_len + 2; i++)
    lrc ^= out[i];
  out[ccid_len + 2] = lrc;
  return ccid_len + 3;
}

static size_t write_header(uint8_t type, uint8_t seq, uint32_t dlen,
                           uint8_t field7, uint8_t *out, size_t cap,
                           size_t total) {
  if (!out || cap < total || total < SEC1210_CCID_HEADER)
    return 0;
  memset(out, 0, total);
  out[0] = type;
  out[1] = (uint8_t)dlen;
  out[2] = (uint8_t)(dlen >> 8);
  out[3] = (uint8_t)(dlen >> 16);
  out[4] = (uint8_t)(dlen >> 24);
  out[6] = seq;
  out[7] = field7;
  return total;
}

size_t sec1210_ccid_slot_status(uint8_t seq, uint8_t *out, size_t cap) {
  return write_header(SEC1210_CCID_SLOT_STATUS, seq, 0, 0, out, cap,
                      SEC1210_CCID_HEADER);
}

size_t sec1210_ccid_power_on(uint8_t seq, uint8_t voltage, uint8_t *out,
                            size_t cap) {
  return write_header(SEC1210_CCID_POWER_ON, seq, 0, voltage, out, cap,
                      SEC1210_CCID_HEADER);
}

size_t sec1210_ccid_power_off(uint8_t seq, uint8_t *out, size_t cap) {
  return write_header(SEC1210_CCID_POWER_OFF, seq, 0, 0, out, cap,
                      SEC1210_CCID_HEADER);
}

bool sec1210_atr_is_t1(const uint8_t *atr, size_t len) {
  if (!atr || len < 2 || (atr[0] != 0x3B && atr[0] != 0x3F))
    return false;
  uint8_t y = atr[1] >> 4;
  size_t i = 2;
  while (y) {
    if (y & 0x1) {
      if (i >= len)
        return false;
      i++;
    }
    if (y & 0x2) {
      if (i >= len)
        return false;
      i++;
    }
    if (y & 0x4) {
      if (i >= len)
        return false;
      i++;
    }
    if (!(y & 0x8))
      break;
    if (i >= len)
      return false;
    uint8_t td = atr[i++];
    uint8_t protocol = td & 0x0F;
    if (protocol != 15)
      return protocol == 1;
    y = td >> 4;
  }
  return false;
}

size_t sec1210_t1_build(uint8_t pcb, const uint8_t *inf, size_t inf_len,
                        uint8_t *out, size_t cap) {
  if (!out || inf_len > 254 || cap < inf_len + 4 || (inf_len > 0 && !inf))
    return 0;
  out[0] = 0x00;
  out[1] = pcb;
  out[2] = (uint8_t)inf_len;
  if (inf_len)
    memcpy(out + 3, inf, inf_len);
  uint8_t lrc = 0;
  for (size_t i = 0; i < inf_len + 3; i++)
    lrc ^= out[i];
  out[inf_len + 3] = lrc;
  return inf_len + 4;
}

bool sec1210_t1_check(const uint8_t *block, size_t len, uint8_t *pcb,
                      uint8_t *inf, size_t inf_cap, size_t *inf_len) {
  if (!block || !pcb || !inf_len || len < 4)
    return false;
  size_t n = block[2];
  if (len != n + 4 || n > inf_cap || (n > 0 && !inf))
    return false;
  uint8_t lrc = 0;
  for (size_t i = 0; i < n + 3; i++)
    lrc ^= block[i];
  if (lrc != block[n + 3])
    return false;
  *pcb = block[1];
  if (n)
    memcpy(inf, block + 3, n);
  *inf_len = n;
  return true;
}

size_t sec1210_ccid_xfr(uint8_t seq, const uint8_t *apdu, size_t apdu_len,
                        uint8_t *out, size_t cap) {
  if (!apdu || apdu_len == 0 || apdu_len > SEC1210_MAX_PAYLOAD)
    return 0;
  size_t total = SEC1210_CCID_HEADER + apdu_len;
  if (write_header(SEC1210_CCID_XFR, seq, (uint32_t)apdu_len, 0, out, cap,
                   total) != total)
    return 0;
  memcpy(out + SEC1210_CCID_HEADER, apdu, apdu_len);
  return total;
}

bool sec1210_t1_on_rblock(uint8_t pcb, bool acked, uint8_t ns, uint8_t nr,
                          uint8_t *tx_pcb, bool *resend_apdu) {
  if (!tx_pcb || !resend_apdu || (pcb & 0xC0) != 0x80)
    return false;
  if (((pcb & 0x10) ? 1 : 0) != (ns ? 1 : 0))
    return false;
  if (acked) {
    *tx_pcb = (uint8_t)(0x80 | (nr ? 0x10 : 0x00));
    *resend_apdu = false;
  } else {
    *tx_pcb = ns ? 0x40 : 0x00;
    *resend_apdu = true;
  }
  return true;
}
