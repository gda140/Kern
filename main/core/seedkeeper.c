#include "seedkeeper.h"

#include <string.h>

static bool no_nul(const uint8_t *p, size_t n);

static const uint8_t SEEDKEEPER_AID[SEEDKEEPER_AID_LEN] = {
    'S', 'e', 'e', 'd', 'K', 'e', 'e', 'p', 'e', 'r'};

static size_t put(uint8_t *out, size_t cap, const uint8_t *src, size_t n) {
  if (!out || cap < n)
    return 0;
  memcpy(out, src, n);
  return n;
}

size_t seedkeeper_apdu_select(uint8_t *out, size_t cap) {
  uint8_t apdu[5 + SEEDKEEPER_AID_LEN] = {0x00, 0xA4, 0x04, 0x00,
                                          SEEDKEEPER_AID_LEN};
  memcpy(apdu + 5, SEEDKEEPER_AID, SEEDKEEPER_AID_LEN);
  return put(out, cap, apdu, sizeof(apdu));
}

size_t seedkeeper_apdu_status(uint8_t *out, size_t cap) {
  const uint8_t apdu[] = {0xB0, 0xA7, 0x00, 0x00};
  return put(out, cap, apdu, sizeof(apdu));
}

size_t seedkeeper_apdu_verify_pin(const uint8_t *pin, size_t pin_len,
                                  uint8_t *out, size_t cap) {
  if (!pin || pin_len < SEEDKEEPER_PIN_MIN || pin_len > SEEDKEEPER_PIN_MAX)
    return 0;
  if (!out || cap < 5 + pin_len)
    return 0;
  out[0] = 0xB0;
  out[1] = 0x42;
  out[2] = 0x00;
  out[3] = 0x00;
  out[4] = (uint8_t)pin_len;
  memcpy(out + 5, pin, pin_len);
  return 5 + pin_len;
}

size_t seedkeeper_apdu_list(uint8_t p2, uint8_t *out, size_t cap) {
  const uint8_t apdu[] = {0xB0, 0xA6, 0x00, p2};
  return put(out, cap, apdu, sizeof(apdu));
}

size_t seedkeeper_apdu_export(uint16_t sid, uint8_t p2, uint8_t *out,
                              size_t cap) {
  const uint8_t apdu[] = {
      0xB0, 0xA2, 0x01, p2, 0x02, (uint8_t)(sid >> 8), (uint8_t)sid};
  return put(out, cap, apdu, sizeof(apdu));
}

bool seedkeeper_header_parse(const uint8_t *buf, size_t len,
                             seedkeeper_header_t *out) {
  if (!buf || !out || len < 15)
    return false;
  uint8_t label_len = buf[14];
  if (label_len > SEEDKEEPER_LABEL_MAX || len < (size_t)15 + label_len)
    return false;

  memset(out, 0, sizeof(*out));
  out->id = (uint16_t)((buf[0] << 8) | buf[1]);
  out->type = buf[2];
  out->origin = buf[3];
  out->export_rights = buf[4];
  out->nb_plain = buf[5];
  out->nb_secure = buf[6];
  out->use_counter = buf[7];
  memcpy(out->fingerprint, buf + 8, 4);
  out->subtype = buf[12];
  memcpy(out->label, buf + 15, label_len);
  out->label[label_len] = '\0';
  return true;
}

bool seedkeeper_status_parse(const uint8_t *buf, size_t len,
                             seedkeeper_status_t *out) {
  if (!buf || !out || len < 10)
    return false;
  out->nb_secrets = (uint16_t)((buf[0] << 8) | buf[1]);
  out->total_memory = (uint16_t)((buf[2] << 8) | buf[3]);
  out->free_memory = (uint16_t)((buf[4] << 8) | buf[5]);
  out->nb_logs_total = (uint16_t)((buf[6] << 8) | buf[7]);
  out->nb_logs_avail = (uint16_t)((buf[8] << 8) | buf[9]);
  return true;
}

int seedkeeper_cards_find(const uint8_t *list, size_t count,
                          const uint8_t key[SEEDKEEPER_CARD_KEY_LEN]) {
  if (!list || !key)
    return -1;
  for (size_t i = 0; i < count; i++) {
    if (memcmp(list + i * SEEDKEEPER_CARD_KEY_LEN, key,
               SEEDKEEPER_CARD_KEY_LEN) == 0)
      return (int)i;
  }
  return -1;
}

bool seedkeeper_cards_valid(const uint8_t *list, size_t len) {
  if (len % SEEDKEEPER_CARD_KEY_LEN != 0 ||
      len > SEEDKEEPER_CARDS_MAX * SEEDKEEPER_CARD_KEY_LEN || (len && !list))
    return false;
  for (size_t at = 0; at < len; at += SEEDKEEPER_CARD_KEY_LEN) {
    if (list[at] != 0x02 && list[at] != 0x03)
      return false;
  }
  return true;
}

bool seedkeeper_card_id(const uint8_t key[SEEDKEEPER_CARD_KEY_LEN], char *out,
                        size_t cap) {
  static const char HEX[] = "0123456789ABCDEF";
  if (!key || !out || cap < SEEDKEEPER_CARD_ID_LEN)
    return false;
  size_t at = 0;
  for (size_t i = 0; i < SEEDKEEPER_CARD_KEY_LEN * 2; i++) {
    if (i && i % 4 == 0)
      out[at++] = ' ';
    uint8_t byte = key[i / 2];
    out[at++] = HEX[(i % 2) ? (byte & 0x0F) : (byte >> 4)];
  }
  out[at] = '\0';
  return true;
}

bool seedkeeper_fingerprint_equal(const uint8_t expected[4],
                                  const uint8_t digest[32]) {
  if (!expected || !digest)
    return false;
  uint8_t diff = 0;
  for (int i = 0; i < 4; i++)
    diff |= (uint8_t)(expected[i] ^ digest[i]);
  return diff == 0;
}

size_t seedkeeper_apdu_secure_init(const uint8_t pubkey[65], uint8_t *out,
                                   size_t cap) {
  if (!pubkey || !out || cap < 70)
    return 0;
  out[0] = 0xB0;
  out[1] = 0x81;
  out[2] = 0x00;
  out[3] = 0x00;
  out[4] = 65;
  memcpy(out + 5, pubkey, 65);
  return 70;
}

bool seedkeeper_pin_tries_left(uint8_t sw1, uint8_t sw2, int *tries) {
  if (sw1 != 0x63 || (sw2 & 0xF0) != 0xC0 || !tries)
    return false;
  *tries = sw2 & 0x0F;
  return true;
}

bool seedkeeper_can_import(const seedkeeper_header_t *header) {
  if (!header || header->export_rights != SEEDKEEPER_EXPORT_ALLOWED)
    return false;
  if (header->type == SEEDKEEPER_TYPE_BIP39)
    return true;
  return header->type == SEEDKEEPER_TYPE_MASTER_SEED &&
         header->subtype == SEEDKEEPER_SUBTYPE_BIP39;
}

bool seedkeeper_can_passphrase(const seedkeeper_header_t *header) {
  return header && header->type == SEEDKEEPER_TYPE_PASSWORD &&
         header->export_rights == SEEDKEEPER_EXPORT_ALLOWED;
}

bool seedkeeper_can_delete(const seedkeeper_header_t *header) {
  return header && header->type != SEEDKEEPER_TYPE_AUTHENTIKEY;
}

bool seedkeeper_can_descriptor(const seedkeeper_header_t *header) {
  return header && header->type == SEEDKEEPER_TYPE_DESCRIPTOR &&
         header->export_rights == SEEDKEEPER_EXPORT_ALLOWED;
}

seedkeeper_decode_t seedkeeper_descriptor_decode(const uint8_t *secret,
                                                 size_t len,
                                                 const uint8_t **text,
                                                 size_t *text_len) {
  if (!secret || !text || !text_len || len < 2)
    return SEEDKEEPER_DECODE_MALFORMED;
  size_t n = ((size_t)secret[0] << 8) | secret[1];
  if (n == 0 || n > SEEDKEEPER_DESCRIPTOR_MAX || len != 2 + n ||
      !no_nul(secret + 2, n))
    return SEEDKEEPER_DECODE_MALFORMED;
  *text = secret + 2;
  *text_len = n;
  return SEEDKEEPER_DECODE_OK;
}

size_t seedkeeper_secret_encode_descriptor(const char *text, uint8_t *out,
                                           size_t cap) {
  if (!text)
    return 0;
  size_t n = strlen(text);
  if (n == 0 || n > SEEDKEEPER_DESCRIPTOR_MAX)
    return 0;
  if (!out || cap < 2 + n)
    return 0;
  out[0] = (uint8_t)(n >> 8);
  out[1] = (uint8_t)n;
  memcpy(out + 2, text, n);
  return 2 + n;
}

bool seedkeeper_export_chunk(const uint8_t *buf, size_t len,
                             const uint8_t **chunk, size_t *chunk_len,
                             bool *last) {
  if (!buf || !chunk || !chunk_len || !last || len < 2)
    return false;
  size_t n = ((size_t)buf[0] << 8) | buf[1];
  if (len < 2 + n)
    return false;
  *chunk = buf + 2;
  *chunk_len = n;
  if (len == 2 + n) {
    *last = false;
    return true;
  }
  if (len < 2 + n + 2)
    return false;
  size_t sig = ((size_t)buf[2 + n] << 8) | buf[3 + n];
  if (len < 2 + n + 2 + sig)
    return false;
  *last = true;
  return true;
}

static bool no_nul(const uint8_t *p, size_t n) {
  for (size_t i = 0; i < n; i++) {
    if (p[i] == 0)
      return false;
  }
  return true;
}

static bool entropy_len_ok(size_t n) {
  return n == 16 || n == 20 || n == 24 || n == 28 || n == 32;
}

seedkeeper_decode_t
seedkeeper_secret_decode(uint8_t type, uint8_t subtype, const uint8_t *secret,
                         size_t len, seedkeeper_secret_form_t *form,
                         const uint8_t **material, size_t *material_len,
                         const uint8_t **passphrase, size_t *passphrase_len) {
  if (!secret || !form || !material || !material_len || !passphrase ||
      !passphrase_len)
    return SEEDKEEPER_DECODE_MALFORMED;

  if (type == SEEDKEEPER_TYPE_BIP39) {
    if (len < 2)
      return SEEDKEEPER_DECODE_MALFORMED;
    size_t n = secret[0];
    if (n == 0 || len < 2 + n || !no_nul(secret + 1, n))
      return SEEDKEEPER_DECODE_MALFORMED;
    size_t pass_len = secret[1 + n];
    if (len < 2 + n + pass_len || !no_nul(secret + 2 + n, pass_len))
      return SEEDKEEPER_DECODE_MALFORMED;
    *form = SEEDKEEPER_SECRET_MNEMONIC;
    *material = secret + 1;
    *material_len = n;
    *passphrase = secret + 2 + n;
    *passphrase_len = pass_len;
    return SEEDKEEPER_DECODE_OK;
  }

  if (type != SEEDKEEPER_TYPE_MASTER_SEED ||
      subtype != SEEDKEEPER_SUBTYPE_BIP39)
    return SEEDKEEPER_DECODE_UNSUPPORTED;
  if (len < 1)
    return SEEDKEEPER_DECODE_MALFORMED;
  size_t ms = secret[0];
  if (len < 1 + ms + 2)
    return SEEDKEEPER_DECODE_MALFORMED;
  size_t off = 1 + ms;
  uint8_t wordlist = secret[off++];
  size_t ent = secret[off++];
  if (len < off + ent + 1)
    return SEEDKEEPER_DECODE_MALFORMED;
  if (wordlist != SEEDKEEPER_WORDLIST_ENGLISH)
    return SEEDKEEPER_DECODE_WORDLIST;
  if (!entropy_len_ok(ent))
    return SEEDKEEPER_DECODE_MALFORMED;
  const uint8_t *entropy = secret + off;
  off += ent;
  size_t pass_len = secret[off++];
  if (len < off + pass_len || !no_nul(secret + off, pass_len))
    return SEEDKEEPER_DECODE_MALFORMED;
  *form = SEEDKEEPER_SECRET_ENTROPY;
  *material = entropy;
  *material_len = ent;
  *passphrase = secret + off;
  *passphrase_len = pass_len;
  return SEEDKEEPER_DECODE_OK;
}

seedkeeper_decode_t seedkeeper_password_decode(const uint8_t *secret,
                                               size_t len,
                                               const uint8_t **password,
                                               size_t *password_len) {
  if (!secret || !password || !password_len || len < 2)
    return SEEDKEEPER_DECODE_MALFORMED;
  size_t n = secret[0];
  if (n == 0 || len < 1 + n || !no_nul(secret + 1, n))
    return SEEDKEEPER_DECODE_MALFORMED;
  size_t off = 1 + n;
  if (off < len) {
    size_t login = secret[off++];
    if (len < off + login || !no_nul(secret + off, login))
      return SEEDKEEPER_DECODE_MALFORMED;
    off += login;
    if (off < len) {
      size_t url = secret[off++];
      if (len != off + url || (url && !no_nul(secret + off, url)))
        return SEEDKEEPER_DECODE_MALFORMED;
    }
  }
  *password = secret + 1;
  *password_len = n;
  return SEEDKEEPER_DECODE_OK;
}

size_t seedkeeper_padded_secret_size(size_t secret_len) {
  size_t pad = 16 - (secret_len % 16);
  if (secret_len > SIZE_MAX - pad)
    return 0;
  return secret_len + pad;
}

size_t seedkeeper_import_header(uint8_t type, uint8_t subtype,
                                uint8_t export_rights, const char *label,
                                uint8_t *out, size_t cap) {
  if (!label)
    return 0;
  size_t label_len = strlen(label);
  if (label_len == 0 || label_len > SEEDKEEPER_LABEL_MAX)
    return 0;
  size_t n = 13 + label_len;
  if (!out || cap < n)
    return 0;
  memset(out, 0, n);
  out[0] = type;
  out[2] = export_rights;
  out[10] = subtype;
  out[12] = (uint8_t)label_len;
  memcpy(out + 13, label, label_len);
  return n;
}

size_t seedkeeper_secret_encode_bip39(const uint8_t *seed, size_t seed_len,
                                      const uint8_t *entropy,
                                      size_t entropy_len,
                                      const uint8_t *passphrase,
                                      size_t pass_len, uint8_t *out,
                                      size_t cap) {
  if (!seed || seed_len == 0 || seed_len > 255 || !entropy ||
      !entropy_len_ok(entropy_len))
    return 0;
  if (pass_len > 255 ||
      (pass_len && (!passphrase || !no_nul(passphrase, pass_len))))
    return 0;
  size_t n = 1 + seed_len + 2 + entropy_len + 1 + pass_len;
  if (!out || cap < n)
    return 0;
  size_t i = 0;
  out[i++] = (uint8_t)seed_len;
  memcpy(out + i, seed, seed_len);
  i += seed_len;
  out[i++] = SEEDKEEPER_WORDLIST_ENGLISH;
  out[i++] = (uint8_t)entropy_len;
  memcpy(out + i, entropy, entropy_len);
  i += entropy_len;
  out[i++] = (uint8_t)pass_len;
  if (pass_len)
    memcpy(out + i, passphrase, pass_len);
  return n;
}

size_t seedkeeper_apdu_import_init(const uint8_t *header, size_t header_len,
                                   uint16_t padded, uint8_t *out, size_t cap) {
  if (!header || header_len == 0 || header_len > 250)
    return 0;
  size_t n = 5 + header_len + 2;
  if (!out || cap < n)
    return 0;
  out[0] = 0xB0;
  out[1] = 0xA1;
  out[2] = 0x01;
  out[3] = SEEDKEEPER_P2_INIT;
  out[4] = (uint8_t)(header_len + 2);
  memcpy(out + 5, header, header_len);
  out[5 + header_len] = (uint8_t)(padded >> 8);
  out[6 + header_len] = (uint8_t)padded;
  return n;
}

size_t seedkeeper_apdu_import_data(uint8_t p2, const uint8_t *chunk,
                                   size_t chunk_len, uint8_t *out, size_t cap) {
  if ((p2 != SEEDKEEPER_P2_NEXT && p2 != SEEDKEEPER_P2_FINAL) ||
      chunk_len > SEEDKEEPER_IMPORT_CHUNK || (chunk_len && !chunk))
    return 0;
  size_t n = 7 + chunk_len;
  if (!out || cap < n)
    return 0;
  out[0] = 0xB0;
  out[1] = 0xA1;
  out[2] = 0x01;
  out[3] = p2;
  out[4] = (uint8_t)(2 + chunk_len);
  out[5] = (uint8_t)(chunk_len >> 8);
  out[6] = (uint8_t)chunk_len;
  if (chunk_len)
    memcpy(out + 7, chunk, chunk_len);
  return n;
}

bool seedkeeper_import_result(const uint8_t *resp, size_t len, uint16_t *id,
                              uint8_t fingerprint[4]) {
  if (!resp || len < 6 || !id || !fingerprint)
    return false;
  *id = (uint16_t)((resp[0] << 8) | resp[1]);
  memcpy(fingerprint, resp + 2, 4);
  return true;
}

size_t seedkeeper_apdu_reset(uint16_t sid, uint8_t *out, size_t cap) {
  const uint8_t apdu[] = {
      0xB0, 0xA5, 0x00, 0x00, 0x02, (uint8_t)(sid >> 8), (uint8_t)sid};
  return put(out, cap, apdu, sizeof(apdu));
}
