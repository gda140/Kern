/*
 * Satochip secure-channel framing.
 *
 * Matches pysatochip SecureChannel: HMAC-SHA1(shared_x, "sc_key")[:16] is
 * the AES-128 key, HMAC-SHA1(shared_x, "sc_mac") is the MAC key. The shared
 * secret is the raw ECDH x-coordinate. The host uses odd AES-CBC counters
 * starting at 1 and steps by 2. The card's response is IV || ct_len ||
 * ciphertext and is not MACed. The primitives come from crypto_utils (PSA).
 */

#ifndef SEEDKEEPER_SC_H
#define SEEDKEEPER_SC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SEEDKEEPER_SC_X_LEN 32
#define SEEDKEEPER_SC_IV_PREFIX 12
#define SEEDKEEPER_SC_MAC_LEN 20
/* PKCS#7 of this still fits in a one-byte APDU Lc after the IV and MAC. */
#define SEEDKEEPER_SC_PLAIN_MAX 192

typedef struct {
  uint8_t aes[16];
  uint8_t mac[20];
  uint32_t counter;
} seedkeeper_sc_t;

/* Derive the session keys. Returns false (and leaves sc wiped) if the
 * crypto backend fails. */
bool seedkeeper_sc_init(seedkeeper_sc_t *sc, const uint8_t shared_x[32]);
void seedkeeper_sc_wipe(seedkeeper_sc_t *sc);

/* IV is iv_prefix || counter as uint32 big-endian. Returns the framed
 * length, or 0 if the plaintext does not fit. Advances the counter by 2. */
size_t seedkeeper_sc_seal(seedkeeper_sc_t *sc, const uint8_t iv_prefix[12],
                          const uint8_t *plain, size_t plain_len, uint8_t *out,
                          size_t cap);

/* Decrypt a card response. Empty plaintext is success with *out_len 0. */
bool seedkeeper_sc_open(const seedkeeper_sc_t *sc, const uint8_t *msg,
                        size_t msg_len, uint8_t *out, size_t cap,
                        size_t *out_len);

/* INIT response: data_size || x || sig_size || DER self-signature.
 * `sig` points into `resp`. */
bool seedkeeper_sc_parse_init(const uint8_t *resp, size_t len, uint8_t x[32],
                              const uint8_t **sig, size_t *sig_len);

/* The rest of an INIT response: sig2_size || sig2 || x_size || authentikey_x.
 * sig2 is the authentikey's signature over resp[0 .. *signed_len), which
 * holds the ephemeral key and its self-signature. `sig2` points into `resp`.
 * Applets that predate the authentikey x-coordinate fail here. */
bool seedkeeper_sc_parse_init_auth(const uint8_t *resp, size_t len,
                                   size_t *signed_len, const uint8_t **sig2,
                                   size_t *sig2_len, uint8_t auth_x[32]);

/* Split a DER ECDSA signature into 32-byte big-endian r and s. Either may
 * be 33 bytes on the wire when its top bit is set. */
bool seedkeeper_sc_der_rs(const uint8_t *sig, size_t len, uint8_t r[32],
                          uint8_t s[32]);

#endif
