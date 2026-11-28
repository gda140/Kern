#include "seedkeeper_sc.h"

#include <string.h>

static void wipe(void *ptr, size_t len) {
  volatile uint8_t *p = ptr;
  while (len--)
    *p++ = 0;
}

static uint8_t xtime(uint8_t x) {
  return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0));
}

static uint8_t gmul(uint8_t a, uint8_t b) {
  uint8_t p = 0;
  for (int i = 0; i < 8; i++) {
    if (b & 1)
      p ^= a;
    uint8_t hi = (uint8_t)(a & 0x80);
    a = (uint8_t)(a << 1);
    if (hi)
      a ^= 0x1b;
    b = (uint8_t)(b >> 1);
  }
  return p;
}

static uint8_t gpow(uint8_t a, int e) {
  uint8_t r = 1;
  while (e) {
    if (e & 1)
      r = gmul(r, a);
    a = gmul(a, a);
    e >>= 1;
  }
  return r;
}

static uint8_t sbox[256];
static uint8_t inv_sbox[256];
static int tables_ready;

static void init_tables(void) {
  if (tables_ready)
    return;
  for (int i = 0; i < 256; i++) {
    uint8_t y = i ? gpow((uint8_t)i, 254) : 0;
    uint8_t r = y;
    uint8_t rot = y;
    for (int k = 0; k < 4; k++) {
      rot = (uint8_t)((rot << 1) | (rot >> 7));
      r ^= rot;
    }
    sbox[i] = (uint8_t)(r ^ 0x63);
  }
  for (int i = 0; i < 256; i++)
    inv_sbox[sbox[i]] = (uint8_t)i;
  tables_ready = 1;
}

static void expand_key(const uint8_t key[16], uint8_t rk[176]) {
  memcpy(rk, key, 16);
  int bytes = 16;
  uint8_t rcon = 1;
  uint8_t t[4];
  while (bytes < 176) {
    memcpy(t, rk + bytes - 4, 4);
    if (bytes % 16 == 0) {
      uint8_t tmp = t[0];
      t[0] = (uint8_t)(sbox[t[1]] ^ rcon);
      t[1] = sbox[t[2]];
      t[2] = sbox[t[3]];
      t[3] = sbox[tmp];
      rcon = xtime(rcon);
    }
    for (int i = 0; i < 4; i++) {
      rk[bytes] = (uint8_t)(rk[bytes - 16] ^ t[i]);
      t[i] = rk[bytes];
      bytes++;
    }
  }
  wipe(t, sizeof(t));
}

static void add_round(uint8_t s[4][4], const uint8_t *rk) {
  for (int c = 0; c < 4; c++) {
    for (int r = 0; r < 4; r++)
      s[r][c] ^= rk[c * 4 + r];
  }
}

static void sub_bytes(uint8_t s[4][4], const uint8_t *box) {
  for (int r = 0; r < 4; r++) {
    for (int c = 0; c < 4; c++)
      s[r][c] = box[s[r][c]];
  }
}

static void shift_rows(uint8_t s[4][4], int left) {
  for (int r = 1; r < 4; r++) {
    uint8_t t[4];
    for (int c = 0; c < 4; c++)
      t[c] = s[r][c];
    for (int c = 0; c < 4; c++) {
      int src = left ? (c + r) & 3 : (c - r + 4) & 3;
      s[r][c] = t[src];
    }
  }
}

static void mix_columns(uint8_t s[4][4]) {
  for (int c = 0; c < 4; c++) {
    uint8_t a0 = s[0][c], a1 = s[1][c], a2 = s[2][c], a3 = s[3][c];
    uint8_t tmp = (uint8_t)(a0 ^ a1 ^ a2 ^ a3);
    s[0][c] ^= (uint8_t)(tmp ^ xtime((uint8_t)(a0 ^ a1)));
    s[1][c] ^= (uint8_t)(tmp ^ xtime((uint8_t)(a1 ^ a2)));
    s[2][c] ^= (uint8_t)(tmp ^ xtime((uint8_t)(a2 ^ a3)));
    s[3][c] ^= (uint8_t)(tmp ^ xtime((uint8_t)(a3 ^ a0)));
  }
}

static void inv_mix_columns(uint8_t s[4][4]) {
  for (int c = 0; c < 4; c++) {
    uint8_t a0 = s[0][c], a1 = s[1][c], a2 = s[2][c], a3 = s[3][c];
    s[0][c] = (uint8_t)(gmul(a0, 0x0e) ^ gmul(a1, 0x0b) ^ gmul(a2, 0x0d) ^
                        gmul(a3, 0x09));
    s[1][c] = (uint8_t)(gmul(a0, 0x09) ^ gmul(a1, 0x0e) ^ gmul(a2, 0x0b) ^
                        gmul(a3, 0x0d));
    s[2][c] = (uint8_t)(gmul(a0, 0x0d) ^ gmul(a1, 0x09) ^ gmul(a2, 0x0e) ^
                        gmul(a3, 0x0b));
    s[3][c] = (uint8_t)(gmul(a0, 0x0b) ^ gmul(a1, 0x0d) ^ gmul(a2, 0x09) ^
                        gmul(a3, 0x0e));
  }
}

static void load_state(uint8_t s[4][4], const uint8_t in[16]) {
  for (int i = 0; i < 16; i++)
    s[i % 4][i / 4] = in[i];
}

static void store_state(const uint8_t s[4][4], uint8_t out[16]) {
  for (int i = 0; i < 16; i++)
    out[i] = s[i % 4][i / 4];
}

static void aes_encrypt(const uint8_t rk[176], const uint8_t in[16],
                        uint8_t out[16]) {
  uint8_t s[4][4];
  load_state(s, in);
  add_round(s, rk);
  for (int round = 1; round < 10; round++) {
    sub_bytes(s, sbox);
    shift_rows(s, 1);
    mix_columns(s);
    add_round(s, rk + round * 16);
  }
  sub_bytes(s, sbox);
  shift_rows(s, 1);
  add_round(s, rk + 160);
  store_state(s, out);
  wipe(s, sizeof(s));
}

static void aes_decrypt(const uint8_t rk[176], const uint8_t in[16],
                        uint8_t out[16]) {
  uint8_t s[4][4];
  load_state(s, in);
  add_round(s, rk + 160);
  for (int round = 9; round >= 1; round--) {
    shift_rows(s, 0);
    sub_bytes(s, inv_sbox);
    add_round(s, rk + round * 16);
    inv_mix_columns(s);
  }
  shift_rows(s, 0);
  sub_bytes(s, inv_sbox);
  add_round(s, rk);
  store_state(s, out);
  wipe(s, sizeof(s));
}

static uint32_t rol(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

static void sha1_block(uint32_t h[5], const uint8_t block[64]) {
  uint32_t w[80];
  for (int i = 0; i < 16; i++) {
    w[i] = ((uint32_t)block[i * 4] << 24) | ((uint32_t)block[i * 4 + 1] << 16) |
           ((uint32_t)block[i * 4 + 2] << 8) | block[i * 4 + 3];
  }
  for (int i = 16; i < 80; i++)
    w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

  uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
  for (int i = 0; i < 80; i++) {
    uint32_t f, k;
    if (i < 20) {
      f = (b & c) | ((~b) & d);
      k = 0x5A827999;
    } else if (i < 40) {
      f = b ^ c ^ d;
      k = 0x6ED9EBA1;
    } else if (i < 60) {
      f = (b & c) | (b & d) | (c & d);
      k = 0x8F1BBCDC;
    } else {
      f = b ^ c ^ d;
      k = 0xCA62C1D6;
    }
    uint32_t t = rol(a, 5) + f + e + k + w[i];
    e = d;
    d = c;
    c = rol(b, 30);
    b = a;
    a = t;
  }
  h[0] += a;
  h[1] += b;
  h[2] += c;
  h[3] += d;
  h[4] += e;
  wipe(w, sizeof(w));
}

static void sha1(const uint8_t *msg, size_t len, uint8_t out[20]) {
  uint32_t h[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
  uint8_t block[64];
  size_t off = 0;
  while (len - off >= 64) {
    sha1_block(h, msg + off);
    off += 64;
  }
  size_t rem = len - off;
  memset(block, 0, sizeof(block));
  if (rem)
    memcpy(block, msg + off, rem);
  block[rem] = 0x80;
  if (rem >= 56) {
    sha1_block(h, block);
    memset(block, 0, sizeof(block));
  }
  uint64_t bits = (uint64_t)len * 8;
  for (int i = 0; i < 8; i++)
    block[63 - i] = (uint8_t)(bits >> (8 * i));
  sha1_block(h, block);
  for (int i = 0; i < 5; i++) {
    out[i * 4] = (uint8_t)(h[i] >> 24);
    out[i * 4 + 1] = (uint8_t)(h[i] >> 16);
    out[i * 4 + 2] = (uint8_t)(h[i] >> 8);
    out[i * 4 + 3] = (uint8_t)h[i];
  }
  wipe(block, sizeof(block));
  wipe(h, sizeof(h));
}

static void hmac_sha1(const uint8_t *key, size_t key_len, const uint8_t *msg,
                      size_t msg_len, uint8_t out[20]) {
  uint8_t k[64];
  memset(k, 0, sizeof(k));
  if (key_len > 64) {
    sha1(key, key_len, k);
  } else if (key_len) {
    memcpy(k, key, key_len);
  }
  uint8_t ipad[64], opad[64];
  for (int i = 0; i < 64; i++) {
    ipad[i] = (uint8_t)(k[i] ^ 0x36);
    opad[i] = (uint8_t)(k[i] ^ 0x5c);
  }
  uint8_t inner[64 + 16 + 2 + SEEDKEEPER_SC_PLAIN_MAX + 16];
  if (msg_len > sizeof(inner) - 64) {
    wipe(k, sizeof(k));
    wipe(ipad, sizeof(ipad));
    wipe(opad, sizeof(opad));
    memset(out, 0, 20);
    return;
  }
  memcpy(inner, ipad, 64);
  if (msg_len)
    memcpy(inner + 64, msg, msg_len);
  uint8_t ih[20];
  sha1(inner, 64 + msg_len, ih);
  uint8_t outer[84];
  memcpy(outer, opad, 64);
  memcpy(outer + 64, ih, 20);
  sha1(outer, 84, out);
  wipe(k, sizeof(k));
  wipe(ipad, sizeof(ipad));
  wipe(opad, sizeof(opad));
  wipe(inner, sizeof(inner));
  wipe(ih, sizeof(ih));
  wipe(outer, sizeof(outer));
}

static void cbc_encrypt(const uint8_t rk[176], const uint8_t iv[16],
                        const uint8_t *in, size_t len, uint8_t *out) {
  uint8_t prev[16];
  memcpy(prev, iv, 16);
  for (size_t off = 0; off < len; off += 16) {
    uint8_t block[16];
    for (int i = 0; i < 16; i++)
      block[i] = (uint8_t)(in[off + i] ^ prev[i]);
    aes_encrypt(rk, block, out + off);
    memcpy(prev, out + off, 16);
    wipe(block, sizeof(block));
  }
  wipe(prev, sizeof(prev));
}

static void cbc_decrypt(const uint8_t rk[176], const uint8_t iv[16],
                        const uint8_t *in, size_t len, uint8_t *out) {
  uint8_t prev[16];
  memcpy(prev, iv, 16);
  for (size_t off = 0; off < len; off += 16) {
    uint8_t cipher[16];
    memcpy(cipher, in + off, 16);
    aes_decrypt(rk, cipher, out + off);
    for (int i = 0; i < 16; i++)
      out[off + i] ^= prev[i];
    memcpy(prev, cipher, 16);
    wipe(cipher, sizeof(cipher));
  }
  wipe(prev, sizeof(prev));
}

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

void seedkeeper_sc_init(seedkeeper_sc_t *sc, const uint8_t shared_x[32]) {
  if (!sc || !shared_x)
    return;
  init_tables();
  uint8_t full[20];
  hmac_sha1(shared_x, 32, (const uint8_t *)"sc_key", 6, full);
  memcpy(sc->aes, full, 16);
  wipe(full, sizeof(full));
  hmac_sha1(shared_x, 32, (const uint8_t *)"sc_mac", 6, sc->mac);
  sc->counter = 1;
}

void seedkeeper_sc_wipe(seedkeeper_sc_t *sc) {
  if (sc)
    wipe(sc, sizeof(*sc));
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

  init_tables();
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

  uint8_t rk[176];
  expand_key(sc->aes, rk);
  memcpy(out, iv, 16);
  out[16] = (uint8_t)(ct_len >> 8);
  out[17] = (uint8_t)ct_len;
  cbc_encrypt(rk, iv, padded, ct_len, out + 18);
  size_t mac_at = 18 + ct_len;
  out[mac_at] = 0;
  out[mac_at + 1] = SEEDKEEPER_SC_MAC_LEN;
  hmac_sha1(sc->mac, SEEDKEEPER_SC_MAC_LEN, out, mac_at, out + mac_at + 2);

  sc->counter += 2;
  wipe(iv, sizeof(iv));
  wipe(padded, sizeof(padded));
  wipe(rk, sizeof(rk));
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

  init_tables();
  uint8_t rk[176];
  expand_key(sc->aes, rk);
  uint8_t plain[SEEDKEEPER_SC_PLAIN_MAX + 16];
  if (ct_len > sizeof(plain)) {
    wipe(rk, sizeof(rk));
    return false;
  }
  cbc_decrypt(rk, msg, msg + 18, ct_len, plain);
  size_t n = 0;
  int ok = pkcs7_strip(plain, ct_len, &n);
  if (!ok || n > cap || (n && !out)) {
    wipe(plain, sizeof(plain));
    wipe(rk, sizeof(rk));
    return false;
  }
  if (n)
    memcpy(out, plain, n);
  *out_len = n;
  wipe(plain, sizeof(plain));
  wipe(rk, sizeof(rk));
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
