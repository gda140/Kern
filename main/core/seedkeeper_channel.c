#include "seedkeeper_channel.h"

#if defined(CONFIG_KERN_BOARD_P4_PICO) && !defined(SIMULATOR)

#include "../utils/secure_mem.h"
#include "crypto_utils.h"
#include "seedkeeper.h"
#include "seedkeeper_sc.h"

#include <mbedtls/ecp.h>
#include <string.h>
#include <wally_core.h>
#include <wally_crypto.h>

static seedkeeper_sc_t session;
static bool session_open;

static int session_rng(void *ctx, unsigned char *out, size_t len) {
  (void)ctx;
  if (!out || len == 0)
    return -1;
  return crypto_random_bytes(out, len) == CRYPTO_OK ? 0 : -1;
}

static bool der_rs(const uint8_t *sig, size_t len, uint8_t r[32],
                   uint8_t s[32]) {
  if (!sig || len < 8 || sig[0] != 0x30 || sig[1] > 127)
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
  if ((lr == 33 && sig[4] != 0x00) || (ls == 33 && sig[5 + lr] != 0x00))
    return false;

  memset(r, 0, 32);
  memset(s, 0, 32);
  size_t rcopy = lr > 32 ? 32 : lr;
  size_t scopy = ls > 32 ? 32 : ls;
  memcpy(r + 32 - rcopy, sig + 4 + lr - rcopy, rcopy);
  memcpy(s + 32 - scopy, sig + 6 + lr + ls - scopy, scopy);
  return true;
}

static bool recover_peer(const uint8_t *msg, size_t msg_len, const uint8_t *sig,
                         size_t sig_len, const uint8_t x[32], uint8_t unc[65]) {
  uint8_t r[32], s[32], hash[32], compact[65];
  bool found = false;
  memset(compact, 0, sizeof(compact));
  if (!der_rs(sig, sig_len, r, s) ||
      wally_sha256(msg, msg_len, hash, sizeof(hash)) != WALLY_OK)
    goto out;
  memcpy(compact + 1, r, 32);
  memcpy(compact + 33, s, 32);
  for (int rec = 0; rec < 4; rec++) {
    uint8_t compressed[EC_PUBLIC_KEY_LEN];
    compact[0] = (uint8_t)(27 + rec);
    if (wally_ec_sig_to_public_key(hash, 32, compact, sizeof(compact),
                                   compressed, sizeof(compressed)) != WALLY_OK)
      continue;
    if (memcmp(compressed + 1, x, 32) != 0) {
      secure_memzero(compressed, sizeof(compressed));
      continue;
    }
    found = wally_ec_public_key_decompress(compressed, sizeof(compressed), unc,
                                           EC_PUBLIC_KEY_UNCOMPRESSED_LEN) ==
            WALLY_OK;
    secure_memzero(compressed, sizeof(compressed));
    break;
  }
out:
  secure_memzero(r, sizeof(r));
  secure_memzero(s, sizeof(s));
  secure_memzero(hash, sizeof(hash));
  secure_memzero(compact, sizeof(compact));
  return found;
}

void seedkeeper_session_close(void) {
  seedkeeper_sc_wipe(&session);
  session_open = false;
}

bool seedkeeper_session_is_open(void) { return session_open; }

sec1210_err_t seedkeeper_session_open(void) {
  seedkeeper_session_close();

  mbedtls_ecp_group grp;
  mbedtls_mpi d;
  mbedtls_ecp_point ours, shared, peer;
  mbedtls_ecp_group_init(&grp);
  mbedtls_mpi_init(&d);
  mbedtls_ecp_point_init(&ours);
  mbedtls_ecp_point_init(&shared);
  mbedtls_ecp_point_init(&peer);

  uint8_t pub[EC_PUBLIC_KEY_UNCOMPRESSED_LEN];
  uint8_t peer_pub[EC_PUBLIC_KEY_UNCOMPRESSED_LEN];
  uint8_t raw[EC_PUBLIC_KEY_UNCOMPRESSED_LEN];
  uint8_t apdu[70];
  uint8_t resp[SEC1210_MAX_APDU];
  sec1210_err_t err = SEC1210_ERR_PROTO;
  size_t olen = 0;

  if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256K1) != 0)
    goto out;
  if (mbedtls_ecp_gen_keypair(&grp, &d, &ours, session_rng, NULL) != 0)
    goto out;
  if (mbedtls_ecp_point_write_binary(&grp, &ours, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                     &olen, pub, sizeof(pub)) != 0 ||
      olen != sizeof(pub))
    goto out;

  size_t apdu_len = seedkeeper_apdu_secure_init(pub, apdu, sizeof(apdu));
  size_t resp_len = 0;
  uint8_t sw1 = 0, sw2 = 0;
  err = sec1210_transmit(apdu, apdu_len, resp, sizeof(resp), &resp_len, &sw1,
                         &sw2);
  if (err != SEC1210_OK)
    goto out;
  if (sw1 != 0x90 || sw2 != 0x00) {
    err = SEC1210_ERR_CARD;
    goto out;
  }

  uint8_t x[32];
  const uint8_t *sig = NULL;
  size_t sig_len = 0;
  if (!seedkeeper_sc_parse_init(resp, resp_len, x, &sig, &sig_len) ||
      !recover_peer(resp, 34, sig, sig_len, x, peer_pub) ||
      mbedtls_ecp_point_read_binary(&grp, &peer, peer_pub, sizeof(peer_pub)) !=
          0 ||
      mbedtls_ecp_check_pubkey(&grp, &peer) != 0 ||
      mbedtls_ecp_mul(&grp, &shared, &d, &peer, session_rng, NULL) != 0)
    goto proto;

  olen = 0;
  if (mbedtls_ecp_point_write_binary(&grp, &shared, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                     &olen, raw, sizeof(raw)) != 0 ||
      olen != sizeof(raw) || raw[0] != 0x04)
    goto proto;

  seedkeeper_sc_init(&session, raw + 1);
  session_open = true;
  err = SEC1210_OK;
  goto out;

proto:
  err = SEC1210_ERR_PROTO;

out:
  mbedtls_mpi_free(&d);
  mbedtls_ecp_point_free(&ours);
  mbedtls_ecp_point_free(&shared);
  mbedtls_ecp_point_free(&peer);
  mbedtls_ecp_group_free(&grp);
  secure_memzero(pub, sizeof(pub));
  secure_memzero(peer_pub, sizeof(peer_pub));
  secure_memzero(raw, sizeof(raw));
  secure_memzero(apdu, sizeof(apdu));
  secure_memzero(resp, sizeof(resp));
  if (err != SEC1210_OK)
    seedkeeper_session_close();
  return err;
}

static bool channel_status(uint8_t sw1, uint8_t sw2) {
  return sw1 == 0x9C && sw2 >= 0x20 && sw2 <= 0x23;
}

static sec1210_err_t transmit_once(const uint8_t *apdu, size_t apdu_len,
                                   uint8_t *resp, size_t resp_cap,
                                   size_t *resp_len, uint8_t *sw1,
                                   uint8_t *sw2) {
  uint8_t prefix[SEEDKEEPER_SC_IV_PREFIX];
  uint8_t
      frame[16 + 2 + SEEDKEEPER_SC_PLAIN_MAX + 16 + 2 + SEEDKEEPER_SC_MAC_LEN];
  uint8_t outer[5 + sizeof(frame)];
  uint8_t raw[SEC1210_MAX_APDU];
  if (crypto_random_bytes(prefix, sizeof(prefix)) != CRYPTO_OK)
    return SEC1210_ERR_IO;
  size_t framed = seedkeeper_sc_seal(&session, prefix, apdu, apdu_len, frame,
                                     sizeof(frame));
  secure_memzero(prefix, sizeof(prefix));
  if (framed == 0 || framed > 255) {
    secure_memzero(frame, sizeof(frame));
    return SEC1210_ERR_ARG;
  }

  outer[0] = 0xB0;
  outer[1] = 0x82;
  outer[2] = 0x00;
  outer[3] = 0x00;
  outer[4] = (uint8_t)framed;
  memcpy(outer + 5, frame, framed);
  secure_memzero(frame, sizeof(frame));

  size_t raw_len = 0;
  uint8_t s1 = 0, s2 = 0;
  sec1210_err_t err =
      sec1210_transmit(outer, 5 + framed, raw, sizeof(raw), &raw_len, &s1, &s2);
  secure_memzero(outer, sizeof(outer));
  if (sw1)
    *sw1 = s1;
  if (sw2)
    *sw2 = s2;
  if (resp_len)
    *resp_len = 0;
  if (err != SEC1210_OK) {
    secure_memzero(raw, sizeof(raw));
    return err;
  }
  if (s1 != 0x90 || s2 != 0x00 || raw_len == 0) {
    secure_memzero(raw, sizeof(raw));
    return SEC1210_OK;
  }

  size_t plain_len = 0;
  if (!seedkeeper_sc_open(&session, raw, raw_len, resp, resp_cap, &plain_len)) {
    secure_memzero(raw, sizeof(raw));
    return SEC1210_ERR_PROTO;
  }
  if (resp_len)
    *resp_len = plain_len;
  secure_memzero(raw, sizeof(raw));
  return SEC1210_OK;
}

sec1210_err_t seedkeeper_session_transmit(const uint8_t *apdu, size_t apdu_len,
                                          uint8_t *resp, size_t resp_cap,
                                          size_t *resp_len, uint8_t *sw1,
                                          uint8_t *sw2) {
  if (!session_open || !apdu || !apdu_len)
    return SEC1210_ERR_ARG;
  sec1210_err_t err =
      transmit_once(apdu, apdu_len, resp, resp_cap, resp_len, sw1, sw2);
  if (err != SEC1210_OK || !sw1 || !sw2 || !channel_status(*sw1, *sw2))
    return err;
  err = seedkeeper_session_open();
  if (err != SEC1210_OK)
    return err;
  return transmit_once(apdu, apdu_len, resp, resp_cap, resp_len, sw1, sw2);
}

#else

sec1210_err_t seedkeeper_session_open(void) { return SEC1210_ERR_IO; }

void seedkeeper_session_close(void) {}

bool seedkeeper_session_is_open(void) { return false; }

sec1210_err_t seedkeeper_session_transmit(const uint8_t *apdu, size_t apdu_len,
                                          uint8_t *resp, size_t resp_cap,
                                          size_t *resp_len, uint8_t *sw1,
                                          uint8_t *sw2) {
  (void)apdu;
  (void)apdu_len;
  (void)resp;
  (void)resp_cap;
  (void)resp_len;
  (void)sw1;
  (void)sw2;
  return SEC1210_ERR_IO;
}

#endif
