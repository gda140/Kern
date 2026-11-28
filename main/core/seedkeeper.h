/*
 * Seedkeeper applet commands.
 *
 * Byte layouts follow the Satochip client (pysatochip CardConnector):
 * SELECT AID "SeedKeeper", status INS 0xA7, list INS 0xA6, plain export
 * INS 0xA2, plain import INS 0xA1, reset INS 0xA5, verify PIN INS 0x42.
 * CLA is 0xB0. This file builds and parses those messages; it does not
 * talk to the reader.
 */

#ifndef SEEDKEEPER_H
#define SEEDKEEPER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SEEDKEEPER_AID_LEN 10
#define SEEDKEEPER_LABEL_MAX 64
#define SEEDKEEPER_PIN_MIN 4
#define SEEDKEEPER_PIN_MAX 16

#define SEEDKEEPER_TYPE_MASTER_SEED 0x10
#define SEEDKEEPER_TYPE_BIP39 0x30
#define SEEDKEEPER_TYPE_ELECTRUM 0x40
#define SEEDKEEPER_TYPE_PASSWORD 0x90
#define SEEDKEEPER_TYPE_AUTHENTIKEY 0xA0
#define SEEDKEEPER_TYPE_DESCRIPTOR 0xC1
#define SEEDKEEPER_DESCRIPTOR_MAX 2048
#define SEEDKEEPER_SUBTYPE_DEFAULT 0x00
#define SEEDKEEPER_SUBTYPE_BIP39 0x01
#define SEEDKEEPER_EXPORT_ALLOWED 0x01

#define SEEDKEEPER_SW_OK 0x9000
#define SEEDKEEPER_SW_PIN_FAILED 0x9C02
#define SEEDKEEPER_SW_NOT_ALLOWED 0x9C03
#define SEEDKEEPER_SW_NOT_SETUP 0x9C04
#define SEEDKEEPER_SW_PIN_REQUIRED 0x9C06
#define SEEDKEEPER_SW_NOT_FOUND 0x9C08
#define SEEDKEEPER_SW_PIN_BLOCKED 0x9C0C
#define SEEDKEEPER_SW_NO_MORE 0x9C12
#define SEEDKEEPER_SW_CHANNEL_REQUIRED 0x9C20
#define SEEDKEEPER_SW_CHANNEL_UNINIT 0x9C21
#define SEEDKEEPER_SW_CHANNEL_IV 0x9C22
#define SEEDKEEPER_SW_CHANNEL_MAC 0x9C23
#define SEEDKEEPER_SW_EXPORT_DENIED 0x9C31

#define SEEDKEEPER_WORDLIST_ENGLISH 0x00

#define SEEDKEEPER_P2_INIT 0x01
#define SEEDKEEPER_P2_NEXT 0x02
#define SEEDKEEPER_P2_FINAL 0x03
#define SEEDKEEPER_IMPORT_CHUNK 128

typedef struct {
  uint16_t id;
  uint8_t type;
  uint8_t origin;
  uint8_t export_rights;
  uint8_t nb_plain;
  uint8_t nb_secure;
  uint8_t use_counter;
  uint8_t fingerprint[4];
  uint8_t subtype;
  char label[SEEDKEEPER_LABEL_MAX + 1];
} seedkeeper_header_t;

typedef struct {
  uint16_t nb_secrets;
  uint16_t total_memory;
  uint16_t free_memory;
  uint16_t nb_logs_total;
  uint16_t nb_logs_avail;
} seedkeeper_status_t;

/* Returns the encoded length, or 0 if `out` is too small. */
size_t seedkeeper_apdu_select(uint8_t *out, size_t cap);
size_t seedkeeper_apdu_status(uint8_t *out, size_t cap);
size_t seedkeeper_apdu_verify_pin(const uint8_t *pin, size_t pin_len,
                                  uint8_t *out, size_t cap);
size_t seedkeeper_apdu_list(uint8_t p2, uint8_t *out, size_t cap);
/* Plaintext export. p2 is SEEDKEEPER_P2_INIT, then SEEDKEEPER_P2_NEXT. */
size_t seedkeeper_apdu_export(uint16_t sid, uint8_t p2, uint8_t *out,
                              size_t cap);

bool seedkeeper_header_parse(const uint8_t *buf, size_t len,
                             seedkeeper_header_t *out);
bool seedkeeper_status_parse(const uint8_t *buf, size_t len,
                             seedkeeper_status_t *out);

/* `digest` is SHA-256(secret). The card stores the first 4 bytes. */
bool seedkeeper_fingerprint_equal(const uint8_t expected[4],
                                  const uint8_t digest[32]);

/* A paired card is known by its compressed authentikey. The device keeps at
 * most SEEDKEEPER_CARDS_MAX of them, packed back to back. */
#define SEEDKEEPER_CARD_KEY_LEN 33
#define SEEDKEEPER_CARDS_MAX 4
/* 66 hex digits in groups of 4, 16 spaces, NUL. */
#define SEEDKEEPER_CARD_ID_LEN 83

/* Index of `key` in `count` packed keys, or -1. */
int seedkeeper_cards_find(const uint8_t *list, size_t count,
                          const uint8_t key[SEEDKEEPER_CARD_KEY_LEN]);

/* True if `list` holds len / 33 well-formed compressed keys, at most
 * SEEDKEEPER_CARDS_MAX of them. */
bool seedkeeper_cards_valid(const uint8_t *list, size_t len);

/* The card ID shown to the user: the compressed authentikey in uppercase
 * hex, in groups of 4. cap must be at least SEEDKEEPER_CARD_ID_LEN. */
bool seedkeeper_card_id(const uint8_t key[SEEDKEEPER_CARD_KEY_LEN], char *out,
                        size_t cap);

/* Uncompressed ephemeral pubkey, 65 bytes. INS 0x81, sent in the clear. */
size_t seedkeeper_apdu_secure_init(const uint8_t pubkey[65], uint8_t *out,
                                   size_t cap);

/* 0x63Cx: tries left in the low nibble. */
bool seedkeeper_pin_tries_left(uint8_t sw1, uint8_t sw2, int *tries);

/* Plaintext-exportable BIP39 secret (entropy form or the older mnemonic). */
bool seedkeeper_can_import(const seedkeeper_header_t *header);

/* Plaintext-exportable Password secret (type 0x90). */
bool seedkeeper_can_passphrase(const seedkeeper_header_t *header);

/* Any listed secret except the card's authentikey certificate. */
bool seedkeeper_can_delete(const seedkeeper_header_t *header);

/* Plaintext-exportable Descriptor secret (type 0xC1). */
bool seedkeeper_can_descriptor(const seedkeeper_header_t *header);

/*
 * One plaintext-export chunk: chunk_size(2) || chunk || optional signature.
 * `last` is set when the signature trailer is present. `chunk` points into
 * `buf`.
 */
bool seedkeeper_export_chunk(const uint8_t *buf, size_t len,
                             const uint8_t **chunk, size_t *chunk_len,
                             bool *last);

typedef enum {
  SEEDKEEPER_SECRET_ENTROPY = 1,
  SEEDKEEPER_SECRET_MNEMONIC,
} seedkeeper_secret_form_t;

typedef enum {
  SEEDKEEPER_DECODE_OK = 0,
  SEEDKEEPER_DECODE_UNSUPPORTED,
  SEEDKEEPER_DECODE_WORDLIST,
  SEEDKEEPER_DECODE_MALFORMED,
} seedkeeper_decode_t;

/*
 * Split an exported secret. `material` and `passphrase` point into `secret`.
 * Entropy form is raw BIP39 entropy (English wordlist only). Mnemonic form
 * is the UTF-8 phrase. A raw master seed is unsupported.
 */
seedkeeper_decode_t
seedkeeper_secret_decode(uint8_t type, uint8_t subtype, const uint8_t *secret,
                         size_t len, seedkeeper_secret_form_t *form,
                         const uint8_t **material, size_t *material_len,
                         const uint8_t **passphrase, size_t *passphrase_len);

/*
 * Password secret: length || password, then an optional login and URL, each
 * length-prefixed. `password` points into `secret`. An empty password, an
 * interior NUL, or a truncated trailer is malformed.
 */
seedkeeper_decode_t seedkeeper_password_decode(const uint8_t *secret,
                                               size_t len,
                                               const uint8_t **password,
                                               size_t *password_len);

/* PKCS#7 length the card reserves for a plaintext secret. 0 if it overflows. */
size_t seedkeeper_padded_secret_size(size_t secret_len);

/*
 * Import INIT header, without the sid. Origin and fingerprint are zero:
 * the card fills those in. Label is a non-empty UTF-8 string, at most
 * SEEDKEEPER_LABEL_MAX bytes.
 */
size_t seedkeeper_import_header(uint8_t type, uint8_t subtype,
                                uint8_t export_rights, const char *label,
                                uint8_t *out, size_t cap);

/*
 * BIP39 master-seed body. `seed` is the 64-byte BIP39 seed. `entropy` is
 * 16, 20, 24, 28 or 32 bytes. The wordlist byte is English.
 */
size_t seedkeeper_secret_encode_bip39(const uint8_t *seed, size_t seed_len,
                                      const uint8_t *entropy,
                                      size_t entropy_len,
                                      const uint8_t *passphrase,
                                      size_t pass_len, uint8_t *out,
                                      size_t cap);

/* INS 0xA1 P1 0x01. `padded` is seedkeeper_padded_secret_size(). */
size_t seedkeeper_apdu_import_init(const uint8_t *header, size_t header_len,
                                   uint16_t padded, uint8_t *out, size_t cap);
/* P2 is SEEDKEEPER_P2_NEXT or SEEDKEEPER_P2_FINAL. Chunk at most 128 bytes. */
size_t seedkeeper_apdu_import_data(uint8_t p2, const uint8_t *chunk,
                                   size_t chunk_len, uint8_t *out, size_t cap);
/* FINAL response: sid || fingerprint[4]. */
bool seedkeeper_import_result(const uint8_t *resp, size_t len, uint16_t *id,
                              uint8_t fingerprint[4]);
/*
 * Descriptor body: length u16be || UTF-8 text. The length counts the text
 * only. Empty text, an interior NUL, or more than SEEDKEEPER_DESCRIPTOR_MAX
 * bytes is rejected. `text` points into `secret`.
 */
seedkeeper_decode_t seedkeeper_descriptor_decode(const uint8_t *secret,
                                                 size_t len,
                                                 const uint8_t **text,
                                                 size_t *text_len);
size_t seedkeeper_secret_encode_descriptor(const char *text, uint8_t *out,
                                           size_t cap);

/* INS 0xA5. Removes one secret. The secret itself is not read. */
size_t seedkeeper_apdu_reset(uint16_t sid, uint8_t *out, size_t cap);

#endif
