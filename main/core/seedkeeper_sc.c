#include "seedkeeper_sc.h"

#include "../utils/secure_mem.h"
#include "crypto_utils.h"

#include <string.h>

static int pkcs7_strip(uint8_t *buf, size_t len, size_t *out_len) {
  if (len == 0 || (len % 16) != 0)
    return 0;
  uint8_t pad = buf[len - 1];
  if (pad == 0 || pad > 16 || pad > len)
    return 0;
  for (size_t i = 0; i < pad; i++) {
    if (buf[len - 1 - i] != pad)
      return 0;
  }
  *out_len = len - pad;
  return 1;
}

bool seedkeeper_sc_init(seedkeeper_sc_t *sc, const uint8_t shared_x[32]) {
  if (!sc || !shared_x)
    return false;
  uint8_t full[CRYPTO_SHA1_SIZE];
  bool ok = crypto_hmac_sha1(shared_x, 32, (const uint8_t *)"sc_key", 6,
                             full) == CRYPTO_OK &&
            crypto_hmac_sha1(shared_x, 32, (const uint8_t *)"sc_mac", 6,
                             sc->mac) == CRYPTO_OK;
  memcpy(sc->aes, full, sizeof(sc->aes));
  secure_memzero(full, sizeof(full));
  sc->counter = 1;
  if (!ok)
    seedkeeper_sc_wipe(sc);
  return ok;
}

void seedkeeper_sc_wipe(seedkeeper_sc_t *sc) {
  if (sc)
    secure_memzero(sc, sizeof(*sc));
}

size_t seedkeeper_sc_seal(seedkeeper_sc_t *sc, const uint8_t iv_prefix[12],
                          const uint8_t *plain, size_t plain_len, uint8_t *out,
                          size_t cap) {
  if (!sc || !iv_prefix || (!plain && plain_len) || !out)
    return 0;
  if (plain_len > SEEDKEEPER_SC_PLAIN_MAX || sc->counter < 1)
    return 0;
  size_t pad = 16 - (plain_len % 16);
  size_t ct_len = plain_len + pad;
  size_t total = 16 + 2 + ct_len + 2 + SEEDKEEPER_SC_MAC_LEN;
  if (cap < total)
    return 0;

  uint8_t iv[16];
  memcpy(iv, iv_prefix, 12);
  iv[12] = (uint8_t)(sc->counter >> 24);
  iv[13] = (uint8_t)(sc->counter >> 16);
  iv[14] = (uint8_t)(sc->counter >> 8);
  iv[15] = (uint8_t)sc->counter;

  uint8_t padded[SEEDKEEPER_SC_PLAIN_MAX + 16];
  if (plain_len)
    memcpy(padded, plain, plain_len);
  memset(padded + plain_len, (int)pad, pad);

  memcpy(out, iv, 16);
  out[16] = (uint8_t)(ct_len >> 8);
  out[17] = (uint8_t)ct_len;
  size_t mac_at = 18 + ct_len;
  out[mac_at] = 0;
  out[mac_at + 1] = SEEDKEEPER_SC_MAC_LEN;
  bool ok = crypto_aes128_cbc_encrypt(sc->aes, iv, padded, ct_len, out + 18) ==
                CRYPTO_OK &&
            crypto_hmac_sha1(sc->mac, SEEDKEEPER_SC_MAC_LEN, out, mac_at,
                             out + mac_at + 2) == CRYPTO_OK;
  secure_memzero(iv, sizeof(iv));
  secure_memzero(padded, sizeof(padded));
  if (!ok) {
    secure_memzero(out, total);
    return 0;
  }

  sc->counter += 2;
  return total;
}

bool seedkeeper_sc_open(const seedkeeper_sc_t *sc, const uint8_t *msg,
                        size_t msg_len, uint8_t *out, size_t cap,
                        size_t *out_len) {
  if (!sc || !msg || !out_len || msg_len < 18)
    return false;
  size_t ct_len = ((size_t)msg[16] << 8) | msg[17];
  if (ct_len == 0 || (ct_len % 16) != 0 || msg_len != 18 + ct_len)
    return false;

  uint8_t plain[SEEDKEEPER_SC_PLAIN_MAX + 16];
  if (ct_len > sizeof(plain))
    return false;
  if (crypto_aes128_cbc_decrypt(sc->aes, msg, msg + 18, ct_len, plain) !=
      CRYPTO_OK) {
    secure_memzero(plain, sizeof(plain));
    return false;
  }
  size_t n = 0;
  int ok = pkcs7_strip(plain, ct_len, &n);
  if (!ok || n > cap || (n && !out)) {
    secure_memzero(plain, sizeof(plain));
    return false;
  }
  if (n)
    memcpy(out, plain, n);
  *out_len = n;
  secure_memzero(plain, sizeof(plain));
  return true;
}

bool seedkeeper_sc_der_rs(const uint8_t *sig, size_t len, uint8_t r[32],
                          uint8_t s[32]) {
  if (!sig || !r || !s || len < 8 || sig[0] != 0x30 || sig[1] > 127)
    return false;
  size_t lt = sig[1];
  if (len < 2 + lt || sig[2] != 0x02)
    return false;
  size_t lr = sig[3];
  if (lr == 0 || lr > 33 || 4 + lr >= 2 + lt)
    return false;
  if (sig[4 + lr] != 0x02)
    return false;
  size_t ls = sig[5 + lr];
  if (ls == 0 || ls > 33 || lt != lr + ls + 4)
    return false;
  /* A 33-byte integer is a 32-byte value with a 0x00 sign byte in front. */
  if ((lr == 33 && sig[4] != 0x00) || (ls == 33 && sig[6 + lr] != 0x00))
    return false;

  memset(r, 0, 32);
  memset(s, 0, 32);
  size_t rcopy = lr > 32 ? 32 : lr;
  size_t scopy = ls > 32 ? 32 : ls;
  memcpy(r + 32 - rcopy, sig + 4 + lr - rcopy, rcopy);
  memcpy(s + 32 - scopy, sig + 6 + lr + ls - scopy, scopy);
  return true;
}

bool seedkeeper_sc_parse_init(const uint8_t *resp, size_t len, uint8_t x[32],
                              const uint8_t **sig, size_t *sig_len) {
  if (!resp || !x || !sig || !sig_len || len < 4)
    return false;
  size_t data_size = ((size_t)resp[0] << 8) | resp[1];
  if (data_size != 32)
    return false;
  size_t msg_size = 2 + data_size;
  if (len < msg_size + 2)
    return false;
  size_t n = ((size_t)resp[msg_size] << 8) | resp[msg_size + 1];
  if (n == 0 || len < msg_size + 2 + n)
    return false;
  memcpy(x, resp + 2, 32);
  *sig = resp + msg_size + 2;
  *sig_len = n;
  return true;
}
