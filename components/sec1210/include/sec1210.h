/*
 * SEC1210 UART CCID reader.
 *
 * The Smartcard Hat (Stephen Rothery, SEC1210 URT) speaks the serial CCID
 * framing from Microchip AN1977: 115200 8N1, no flow control. On this Pico
 * the hat's TX lands on GPIO22 and the hat's RX on GPIO20, so the UART is
 * wired TX=GPIO20, RX=GPIO22. UART0 stays the console.
 */

#ifndef SEC1210_H
#define SEC1210_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SEC1210_MAX_ATR 33
#define SEC1210_MAX_APDU 768

typedef enum {
  SEC1210_OK = 0,
  SEC1210_ERR_ARG,
  SEC1210_ERR_IO,
  SEC1210_ERR_NAK,
  SEC1210_ERR_TIMEOUT,
  SEC1210_ERR_PROTO,
  SEC1210_ERR_CARD,
} sec1210_err_t;

typedef enum {
  SEC1210_CARD_ABSENT = 0,
  SEC1210_CARD_INACTIVE,
  SEC1210_CARD_ACTIVE,
} sec1210_card_t;

sec1210_err_t sec1210_init(void);
void sec1210_deinit(void);

sec1210_err_t sec1210_slot_status(sec1210_card_t *card);

/* Powers the card and returns its ATR. The card stays powered until
 * sec1210_power_off(). */
sec1210_err_t sec1210_power_on(uint8_t *atr, size_t atr_cap, size_t *atr_len);
sec1210_err_t sec1210_power_off(void);

/* Short APDU exchange. On success, *resp_len is the response body without
 * the two status bytes, which are written to *sw1 and *sw2. Buffers that
 * held the command are wiped inside the driver. */
sec1210_err_t sec1210_transmit(const uint8_t *apdu, size_t apdu_len,
                               uint8_t *resp, size_t resp_cap, size_t *resp_len,
                               uint8_t *sw1, uint8_t *sw2);

const char *sec1210_err_str(sec1210_err_t err);

/* Hex of the last CCID message seen by a failed exchange. Empty if none. */
const char *sec1210_last_detail(void);

#ifdef __cplusplus
}
#endif

#endif
