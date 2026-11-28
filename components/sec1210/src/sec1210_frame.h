/*
 * Serial CCID framing for the SEC1210, independent of the UART.
 *
 * A command is SYNC (0x03), ACK (0x06), a CCID message, then an LRC that is
 * the XOR of every preceding byte. A rejected frame is SYNC, NAK (0x15),
 * LRC. The reader may also send a one-byte time extension (0x80-0xFF) or a
 * slot-change notice (0x50, then 0x02 absent / 0x03 present).
 */

#ifndef SEC1210_FRAME_H
#define SEC1210_FRAME_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SEC1210_CCID_HEADER 10
#define SEC1210_MAX_PAYLOAD 768
#define SEC1210_MAX_CCID (SEC1210_CCID_HEADER + SEC1210_MAX_PAYLOAD)
#define SEC1210_MAX_FRAME (2 + SEC1210_MAX_CCID + 1)

#define SEC1210_SYNC 0x03
#define SEC1210_ACK 0x06
#define SEC1210_NAK 0x15
#define SEC1210_NOTIFY 0x50

#define SEC1210_CCID_POWER_ON 0x62
#define SEC1210_CCID_POWER_OFF 0x63
#define SEC1210_CCID_SLOT_STATUS 0x65
#define SEC1210_CCID_XFR 0x6F
#define SEC1210_CCID_DATA 0x80
#define SEC1210_CCID_SLOT 0x81

typedef enum {
  SEC1210_FEED_NEED_MORE = 0,
  SEC1210_FEED_FRAME,
  SEC1210_FEED_NAK,
  SEC1210_FEED_SLOT,
  SEC1210_FEED_WAIT,
  SEC1210_FEED_ERROR,
} sec1210_feed_t;

typedef struct {
  uint8_t state;
  uint8_t ccid[SEC1210_MAX_CCID];
  size_t have;
  size_t need;
  uint8_t lrc;
  uint8_t slot;
} sec1210_parser_t;

void sec1210_parser_reset(sec1210_parser_t *parser);

/* On SEC1210_FEED_FRAME the message is in parser->ccid, length parser->have.
 * Copy it out before feeding another byte. */
sec1210_feed_t sec1210_parser_byte(sec1210_parser_t *parser, uint8_t byte);

/* Returns the encoded length, or 0 if the buffer is too small. */
size_t sec1210_frame_encode(const uint8_t *ccid, size_t ccid_len, uint8_t *out,
                            size_t out_cap);

size_t sec1210_ccid_slot_status(uint8_t seq, uint8_t *out, size_t cap);
/* voltage is the CCID bPowerSelect: 1 = 5 V, 2 = 3 V, 3 = 1.8 V. */
size_t sec1210_ccid_power_on(uint8_t seq, uint8_t voltage, uint8_t *out,
                            size_t cap);
size_t sec1210_ccid_power_off(uint8_t seq, uint8_t *out, size_t cap);
size_t sec1210_ccid_xfr(uint8_t seq, const uint8_t *apdu, size_t apdu_len,
                        uint8_t *out, size_t cap);

/* True when the ATR's first offered protocol is T=1. */
bool sec1210_atr_is_t1(const uint8_t *atr, size_t len);

/* T=1 block: NAD 0x00, PCB, LEN, INF, LRC. Returns the block length, or 0. */
size_t sec1210_t1_build(uint8_t pcb, const uint8_t *inf, size_t inf_len,
                        uint8_t *out, size_t cap);

/* Checks the LRC and copies PCB and INF. */
bool sec1210_t1_check(const uint8_t *block, size_t len, uint8_t *pcb,
                      uint8_t *inf, size_t inf_cap, size_t *inf_len);

/* Answer a card R-block (pcb) inside one APDU exchange. ns and nr are the
 * host's current N(S) and expected N(R); acked is true once the card has sent
 * its first I-block, so it holds our command. Before that the card lost our
 * I-block and *resend_apdu is set. After it the card lost our R-block ack, so
 * only that ack goes again: resending the APDU would run it a second time.
 * Returns false if the R-block's N(R) does not match ns. */
bool sec1210_t1_on_rblock(uint8_t pcb, bool acked, uint8_t ns, uint8_t nr,
                          uint8_t *tx_pcb, bool *resend_apdu);

#endif
