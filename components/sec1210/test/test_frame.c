/*
 * Host checks for the SEC1210 frame codec and the Seedkeeper APDU builders.
 * Compile: make -C components/sec1210/test run
 */

#include "sec1210_frame.h"
#include "seedkeeper.h"
#include "seedkeeper_sc.h"

#include <stdio.h>
#include <string.h>

static int passed;
static int failed;

static void expect(const char *name, int ok) {
  if (ok) {
    printf("PASS %s\n", name);
    passed++;
  } else {
    printf("FAIL %s\n", name);
    failed++;
  }
}

static int feed_all(const uint8_t *bytes, size_t len, sec1210_parser_t *parser,
                    sec1210_feed_t *last) {
  sec1210_parser_reset(parser);
  *last = SEC1210_FEED_NEED_MORE;
  for (size_t i = 0; i < len; i++) {
    *last = sec1210_parser_byte(parser, bytes[i]);
    if (*last == SEC1210_FEED_ERROR)
      return 0;
    if (i + 1 < len &&
        (*last == SEC1210_FEED_FRAME || *last == SEC1210_FEED_NAK))
      return 0;
  }
  return 1;
}

static void test_slot_status_frame(void) {
  uint8_t ccid[10];
  size_t n = sec1210_ccid_slot_status(0x01, ccid, sizeof(ccid));
  uint8_t frame[16];
  size_t flen = sec1210_frame_encode(ccid, n, frame, sizeof(frame));
  const uint8_t expect_frame[] = {0x03, 0x06, 0x65, 0x00, 0x00, 0x00, 0x00,
                                  0x00, 0x01, 0x00, 0x00, 0x00, 0x61};
  expect("slot status frame",
         n == 10 && flen == sizeof(expect_frame) &&
             memcmp(frame, expect_frame, sizeof(expect_frame)) == 0);

  sec1210_parser_t parser;
  sec1210_feed_t last;
  int ok = feed_all(expect_frame, sizeof(expect_frame), &parser, &last);
  expect("parse slot status",
         ok && last == SEC1210_FEED_FRAME && parser.have == 10 &&
             memcmp(parser.ccid, ccid, 10) == 0);
}

static void test_nak_and_prefix(void) {
  const uint8_t nak[] = {0x03, 0x15, 0x16};
  sec1210_parser_t parser;
  sec1210_feed_t last;
  expect("nak", feed_all(nak, sizeof(nak), &parser, &last) &&
                    last == SEC1210_FEED_NAK);

  uint8_t ccid[10];
  sec1210_ccid_power_on(0x02, 1, ccid, sizeof(ccid));
  expect("power on is 5V", ccid[0] == 0x62 && ccid[7] == 1);
  uint8_t frame[16];
  size_t flen = sec1210_frame_encode(ccid, 10, frame, sizeof(frame));
  uint8_t stream[1 + 2 + 16];
  stream[0] = 0x80;
  stream[1] = 0x50;
  stream[2] = 0x03;
  memcpy(stream + 3, frame, flen);

  sec1210_parser_reset(&parser);
  sec1210_feed_t feeds[8];
  int nfeeds = 0;
  int err = 0;
  for (size_t i = 0; i < 3 + flen; i++) {
    sec1210_feed_t f = sec1210_parser_byte(&parser, stream[i]);
    if (f == SEC1210_FEED_ERROR)
      err = 1;
    if (f != SEC1210_FEED_NEED_MORE && nfeeds < 8)
      feeds[nfeeds++] = f;
  }
  expect("wait, slot, then frame",
         !err && nfeeds == 3 && feeds[0] == SEC1210_FEED_WAIT &&
             feeds[1] == SEC1210_FEED_SLOT && parser.slot == 0x03 &&
             feeds[2] == SEC1210_FEED_FRAME && parser.have == 10);
}

static void test_bad_lrc(void) {
  uint8_t ccid[10];
  sec1210_ccid_slot_status(1, ccid, sizeof(ccid));
  uint8_t frame[16];
  size_t flen = sec1210_frame_encode(ccid, 10, frame, sizeof(frame));
  frame[flen - 1] ^= 0xFF;
  sec1210_parser_t parser;
  sec1210_feed_t last = SEC1210_FEED_NEED_MORE;
  for (size_t i = 0; i < flen; i++)
    last = sec1210_parser_byte(&parser, frame[i]);
  expect("bad lrc", last == SEC1210_FEED_ERROR);
}

static void test_xfr_roundtrip(void) {
  const uint8_t apdu[] = {0x00, 0xA4, 0x04, 0x00, 0x01, 0xAA};
  uint8_t ccid[32];
  size_t n = sec1210_ccid_xfr(7, apdu, sizeof(apdu), ccid, sizeof(ccid));
  uint8_t frame[40];
  size_t flen = sec1210_frame_encode(ccid, n, frame, sizeof(frame));
  sec1210_parser_t parser;
  sec1210_feed_t last;
  int ok = feed_all(frame, flen, &parser, &last);
  expect("xfr roundtrip",
         ok && n == 16 && last == SEC1210_FEED_FRAME && parser.have == n &&
             memcmp(parser.ccid, ccid, n) == 0 &&
             memcmp(parser.ccid + 10, apdu, sizeof(apdu)) == 0);
}

static void test_seedkeeper(void) {
  uint8_t apdu[32];
  size_t n = seedkeeper_apdu_select(apdu, sizeof(apdu));
  const uint8_t aid[] = {'S', 'e', 'e', 'd', 'K', 'e', 'e', 'p', 'e', 'r'};
  expect("select", n == 15 && apdu[0] == 0x00 && apdu[1] == 0xA4 &&
                       apdu[4] == 10 && memcmp(apdu + 5, aid, 10) == 0);

  n = seedkeeper_apdu_status(apdu, sizeof(apdu));
  const uint8_t status[] = {0xB0, 0xA7, 0x00, 0x00};
  expect("status apdu", n == 4 && memcmp(apdu, status, 4) == 0);

  const uint8_t pin[] = {'1', '2', '3', '4'};
  n = seedkeeper_apdu_verify_pin(pin, 4, apdu, sizeof(apdu));
  expect("verify pin", n == 9 && apdu[1] == 0x42 && apdu[4] == 4 &&
                           memcmp(apdu + 5, pin, 4) == 0);
  expect("pin too short", seedkeeper_apdu_verify_pin(pin, 3, apdu, sizeof(apdu)) == 0);

  n = seedkeeper_apdu_export(0x0007, SEEDKEEPER_P2_INIT, apdu, sizeof(apdu));
  const uint8_t exp[] = {0xB0, 0xA2, 0x01, 0x01, 0x02, 0x00, 0x07};
  expect("export", n == 7 && memcmp(apdu, exp, 7) == 0);

  uint8_t hdr[15 + 4] = {0x00, 0x07, 0x30, 0x01, 0x01, 0x00, 0x00, 0x00,
                         0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x00, 0x04, 'm',
                         'a',  'i',  'n'};
  seedkeeper_header_t header;
  expect("header", seedkeeper_header_parse(hdr, sizeof(hdr), &header) &&
                       header.id == 7 && header.type == SEEDKEEPER_TYPE_BIP39 &&
                       header.export_rights == SEEDKEEPER_EXPORT_ALLOWED &&
                       header.fingerprint[0] == 0xAA &&
                       strcmp(header.label, "main") == 0);
  hdr[14] = 80;
  expect("label too long",
         !seedkeeper_header_parse(hdr, sizeof(hdr), &header));

  const uint8_t st[] = {0x00, 0x03, 0x10, 0x00, 0x0F, 0x00, 0x00, 0x0A,
                        0x00, 0x04};
  seedkeeper_status_t status_out;
  expect("status parse",
         seedkeeper_status_parse(st, sizeof(st), &status_out) &&
             status_out.nb_secrets == 3 && status_out.total_memory == 0x1000 &&
             status_out.free_memory == 0x0F00 &&
             status_out.nb_logs_avail == 4);

  uint8_t digest[32] = {0xAA, 0xBB, 0xCC, 0xDD};
  uint8_t fp[4] = {0xAA, 0xBB, 0xCC, 0xDD};
  expect("fingerprint", seedkeeper_fingerprint_equal(fp, digest));
  digest[3] ^= 1;
  expect("fingerprint mismatch", !seedkeeper_fingerprint_equal(fp, digest));
}

static void test_t1(void) {
  const uint8_t atr[] = {0x3B, 0xDC, 0x18, 0xFF, 0x81, 0x91, 0xFE, 0x1F, 0xC3,
                         0x80, 0x73, 0xC8, 0x21, 0x13, 0x66, 0x05, 0x03, 0x63,
                         0x51, 0x00, 0x02, 0x50};
  expect("seedkeeper atr is t1", sec1210_atr_is_t1(atr, sizeof(atr)));
  const uint8_t t0_atr[] = {0x3B, 0x00};
  expect("t0 atr is not t1", !sec1210_atr_is_t1(t0_atr, sizeof(t0_atr)));

  uint8_t ifsd = 0xFE;
  uint8_t block[8];
  size_t n = sec1210_t1_build(0xC1, &ifsd, 1, block, sizeof(block));
  uint8_t pcb = 0;
  uint8_t inf[4];
  size_t inf_len = 0;
  expect("ifs block",
         n == 5 && sec1210_t1_check(block, n, &pcb, inf, sizeof(inf), &inf_len) &&
             pcb == 0xC1 && inf_len == 1 && inf[0] == 0xFE);
  block[n - 1] ^= 0xFF;
  expect("ifs bad lrc",
         !sec1210_t1_check(block, n, &pcb, inf, sizeof(inf), &inf_len));

  uint8_t tx = 0xFF;
  bool resend = false;
  expect("r-block before ack resends the apdu",
         sec1210_t1_on_rblock(0x91, false, 1, 0, &tx, &resend) && resend &&
             tx == 0x40);
  expect("r-block before ack, ns 0",
         sec1210_t1_on_rblock(0x81, false, 0, 1, &tx, &resend) && resend &&
             tx == 0x00);
  expect("r-block in a chained reply resends only the ack",
         sec1210_t1_on_rblock(0x81, true, 0, 1, &tx, &resend) && !resend &&
             tx == 0x90);
  expect("r-block in a chained reply, nr 0",
         sec1210_t1_on_rblock(0x92, true, 1, 0, &tx, &resend) && !resend &&
             tx == 0x80);
  expect("r-block with the wrong n(r)",
         !sec1210_t1_on_rblock(0x80, true, 1, 0, &tx, &resend) &&
             !sec1210_t1_on_rblock(0x90, false, 0, 0, &tx, &resend));
  expect("not an r-block", !sec1210_t1_on_rblock(0xC3, true, 0, 0, &tx, &resend));
}

static int hexeq(const uint8_t *got, size_t n, const char *hex) {
  if (strlen(hex) != n * 2)
    return 0;
  for (size_t i = 0; i < n; i++) {
    unsigned int byte = 0;
    if (sscanf(hex + i * 2, "%02x", &byte) != 1 || got[i] != (uint8_t)byte)
      return 0;
  }
  return 1;
}

static void test_secure_channel(void) {
  uint8_t shared[32];
  memset(shared, 0x11, sizeof(shared));
  seedkeeper_sc_t sc;
  expect("sc init", seedkeeper_sc_init(&sc, shared));
  const uint8_t prefix[12] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                              0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb};
  const char *plain = "hello seedkeeper";
  uint8_t frame[256];
  size_t n = seedkeeper_sc_seal(&sc, prefix, (const uint8_t *)plain, 16, frame,
                                sizeof(frame));
  const char *frame1 =
      "00112233445566778899aabb000000010020267f74505d67bf2f7080b8785d29ae82"
      "3b27a3a4542aae4eb06a2e7b47112c22001497170517b5940249ee21108ca8cd1037"
      "aa6aeb7b";
  expect("seal counter 1", n == strlen(frame1) / 2 && hexeq(frame, n, frame1));

  uint8_t opened[32];
  size_t opened_len = 0;
  expect("open sealed",
         seedkeeper_sc_open(&sc, frame, 16 + 2 + 32, opened, sizeof(opened),
                            &opened_len) &&
             opened_len == 16 && memcmp(opened, plain, 16) == 0);

  n = seedkeeper_sc_seal(&sc, prefix, (const uint8_t *)plain, 16, frame,
                         sizeof(frame));
  const char *frame3 =
      "00112233445566778899aabb00000003002025003caac680c265517aca7d8a12ebfb"
      "9791926e4920682c82cc8b726643b797001457202f1513a7aac10a530978f3a12f2d"
      "bec47fc4";
  expect("seal counter 3",
         n == strlen(frame3) / 2 && hexeq(frame, n, frame3));
  seedkeeper_sc_wipe(&sc);

  uint8_t init[4 + 32 + 2 + 2] = {0x00, 0x20};
  memset(init + 2, 0xAB, 32);
  init[34] = 0x00;
  init[35] = 0x02;
  init[36] = 0x30;
  init[37] = 0x00;
  uint8_t x[32];
  const uint8_t *sig = NULL;
  size_t sig_len = 0;
  expect("parse init", seedkeeper_sc_parse_init(init, sizeof(init), x, &sig,
                                                &sig_len) &&
                           memcmp(x, init + 2, 32) == 0 && sig_len == 2 &&
                           sig[0] == 0x30);
  init[0] = 0x00;
  init[1] = 0x21;
  expect("parse init rejects non-32 x",
         !seedkeeper_sc_parse_init(init, sizeof(init), x, &sig, &sig_len));
}

static void test_secret_decode(void) {
  const uint8_t mnemonic[] = {4, 'w', 'o', 'r', 'd', 3, 'a', 'b', 'c', 0, 0};
  seedkeeper_secret_form_t form = 0;
  const uint8_t *material = NULL;
  const uint8_t *pass = NULL;
  size_t material_len = 0, pass_len = 0;
  expect("decode mnemonic",
         seedkeeper_secret_decode(SEEDKEEPER_TYPE_BIP39, 0, mnemonic,
                                  sizeof(mnemonic), &form, &material,
                                  &material_len, &pass, &pass_len) ==
                 SEEDKEEPER_DECODE_OK &&
             form == SEEDKEEPER_SECRET_MNEMONIC && material_len == 4 &&
             pass_len == 3 && memcmp(pass, "abc", 3) == 0);

  uint8_t entropy[1 + 4 + 2 + 16 + 1] = {4, 1, 2, 3, 4, 0, 16};
  memset(entropy + 7, 0x5A, 16);
  entropy[23] = 0;
  expect("decode bip39 entropy",
         seedkeeper_secret_decode(SEEDKEEPER_TYPE_MASTER_SEED,
                                  SEEDKEEPER_SUBTYPE_BIP39, entropy,
                                  sizeof(entropy), &form, &material,
                                  &material_len, &pass, &pass_len) ==
                 SEEDKEEPER_DECODE_OK &&
             form == SEEDKEEPER_SECRET_ENTROPY && material_len == 16 &&
             material[0] == 0x5A && pass_len == 0);

  entropy[5] = 1;
  expect("decode rejects other wordlist",
         seedkeeper_secret_decode(SEEDKEEPER_TYPE_MASTER_SEED,
                                  SEEDKEEPER_SUBTYPE_BIP39, entropy,
                                  sizeof(entropy), &form, &material,
                                  &material_len, &pass, &pass_len) ==
             SEEDKEEPER_DECODE_WORDLIST);

  const uint8_t chunk[] = {0x00, 0x02, 0xAA, 0xBB, 0x00, 0x01, 0xCC};
  const uint8_t *part = NULL;
  size_t part_len = 0;
  bool last = false;
  expect("export chunk last",
         seedkeeper_export_chunk(chunk, sizeof(chunk), &part, &part_len,
                                 &last) &&
             part_len == 2 && part[0] == 0xAA && last);
  expect("export chunk more",
         seedkeeper_export_chunk(chunk, 4, &part, &part_len, &last) &&
             part_len == 2 && !last);

  uint8_t pin_apdu[9];
  expect("pin keeps leading zeros",
         seedkeeper_apdu_verify_pin((const uint8_t *)"0123", 4, pin_apdu,
                                    sizeof(pin_apdu)) == 9 &&
             pin_apdu[5] == '0');
  int tries = -1;
  expect("pin tries", seedkeeper_pin_tries_left(0x63, 0xC2, &tries) && tries == 2);
  expect("pin blocked is not tries",
         !seedkeeper_pin_tries_left(0x9C, 0x0C, &tries));
}

static void test_secret_import(void) {
  uint8_t seed[64];
  uint8_t entropy[16];
  memset(seed, 0x22, sizeof(seed));
  memset(entropy, 0x33, sizeof(entropy));
  uint8_t body[128];
  size_t n = seedkeeper_secret_encode_bip39(seed, sizeof(seed), entropy,
                                            sizeof(entropy), NULL, 0, body,
                                            sizeof(body));
  expect("encode bip39", n == 84 && body[0] == 64 && body[65] == 0 &&
                             body[66] == 16 && body[83] == 0);
  seedkeeper_secret_form_t form;
  const uint8_t *mat = NULL;
  const uint8_t *pass = NULL;
  size_t mat_len = 0;
  size_t pass_len = 0;
  expect("encode decodes",
         seedkeeper_secret_decode(SEEDKEEPER_TYPE_MASTER_SEED,
                                  SEEDKEEPER_SUBTYPE_BIP39, body, n, &form, &mat,
                                  &mat_len, &pass, &pass_len) ==
                 SEEDKEEPER_DECODE_OK &&
             form == SEEDKEEPER_SECRET_ENTROPY && mat_len == 16 &&
             memcmp(mat, entropy, 16) == 0 && pass_len == 0);
  expect("pad block", seedkeeper_padded_secret_size(16) == 32);
  expect("pad tail", seedkeeper_padded_secret_size(n) == 96);
  expect("empty label rejected",
         seedkeeper_import_header(SEEDKEEPER_TYPE_MASTER_SEED,
                                  SEEDKEEPER_SUBTYPE_BIP39,
                                  SEEDKEEPER_EXPORT_ALLOWED, "", body,
                                  sizeof(body)) == 0);

  uint8_t header[32];
  size_t h = seedkeeper_import_header(
      SEEDKEEPER_TYPE_MASTER_SEED, SEEDKEEPER_SUBTYPE_BIP39,
      SEEDKEEPER_EXPORT_ALLOWED, "ab", header, sizeof(header));
  expect("import header", h == 15 && header[0] == 0x10 && header[1] == 0 &&
                              header[2] == 0x01 && header[10] == 0x01 &&
                              header[12] == 2 && header[13] == 'a' &&
                              header[14] == 'b');

  uint8_t apdu[160];
  uint16_t padded = (uint16_t)seedkeeper_padded_secret_size(n);
  size_t an =
      seedkeeper_apdu_import_init(header, h, padded, apdu, sizeof(apdu));
  expect("import init", an == 5 + h + 2 && apdu[0] == 0xB0 && apdu[1] == 0xA1 &&
                            apdu[2] == 0x01 && apdu[3] == 0x01 &&
                            apdu[4] == (uint8_t)(h + 2) && apdu[an - 2] == 0 &&
                            apdu[an - 1] == (uint8_t)padded);

  const uint8_t chunk[] = {0xAA, 0xBB, 0xCC};
  an = seedkeeper_apdu_import_data(SEEDKEEPER_P2_FINAL, chunk, 3, apdu,
                                   sizeof(apdu));
  expect("import final", an == 10 && apdu[3] == 0x03 && apdu[4] == 5 &&
                             apdu[5] == 0 && apdu[6] == 3 && apdu[7] == 0xAA);
  expect("import chunk too big",
         seedkeeper_apdu_import_data(SEEDKEEPER_P2_NEXT, body, 129, apdu,
                                     sizeof(apdu)) == 0);

  const uint8_t resp[] = {0x00, 0x09, 0x11, 0x22, 0x33, 0x44};
  uint16_t id = 0;
  uint8_t fp[4];
  expect("import result",
         seedkeeper_import_result(resp, sizeof(resp), &id, fp) && id == 9 &&
             fp[0] == 0x11 && fp[3] == 0x44);

  an = seedkeeper_apdu_reset(9, apdu, sizeof(apdu));
  const uint8_t reset[] = {0xB0, 0xA5, 0x00, 0x00, 0x02, 0x00, 0x09};
  expect("reset secret", an == 7 && memcmp(apdu, reset, 7) == 0);
}

static void test_password_decode(void) {
  const uint8_t plain[] = {0x02, 'h', 'i'};
  const uint8_t *password = NULL;
  size_t n = 0;
  expect("password",
         seedkeeper_password_decode(plain, sizeof(plain), &password, &n) ==
             SEEDKEEPER_DECODE_OK &&
             n == 2 && password[0] == 'h' && password[1] == 'i');

  const uint8_t full[] = {0x02, 'h', 'i', 0x02, 'a', 'b', 0x02, 'c', 'd'};
  expect("password with login and url",
         seedkeeper_password_decode(full, sizeof(full), &password, &n) ==
             SEEDKEEPER_DECODE_OK &&
             n == 2 && password[0] == 'h');

  const uint8_t empty[] = {0x00};
  expect("empty password rejected",
         seedkeeper_password_decode(empty, sizeof(empty), &password, &n) ==
             SEEDKEEPER_DECODE_MALFORMED);
  const uint8_t nul[] = {0x03, 'a', 0x00, 'b'};
  expect("password nul rejected",
         seedkeeper_password_decode(nul, sizeof(nul), &password, &n) ==
             SEEDKEEPER_DECODE_MALFORMED);
  const uint8_t short_tail[] = {0x01, 'a', 0x02, 'b'};
  expect("password tail rejected",
         seedkeeper_password_decode(short_tail, sizeof(short_tail), &password,
                                    &n) == SEEDKEEPER_DECODE_MALFORMED);

  seedkeeper_header_t header = {0};
  header.type = SEEDKEEPER_TYPE_PASSWORD;
  header.export_rights = SEEDKEEPER_EXPORT_ALLOWED;
  expect("password can load", seedkeeper_can_passphrase(&header));
  header.export_rights = 0x02;
  expect("secure-only password stays", !seedkeeper_can_passphrase(&header));
  header.type = SEEDKEEPER_TYPE_BIP39;
  header.export_rights = SEEDKEEPER_EXPORT_ALLOWED;
  expect("mnemonic is not a password", !seedkeeper_can_passphrase(&header));

  expect("null secret stays", !seedkeeper_can_delete(NULL));
  header.type = SEEDKEEPER_TYPE_AUTHENTIKEY;
  expect("authentikey stays", !seedkeeper_can_delete(&header));
  header.type = SEEDKEEPER_TYPE_MASTER_SEED;
  header.export_rights = 0x02;
  expect("secure-only masterseed can be deleted",
         seedkeeper_can_delete(&header));
  header.type = SEEDKEEPER_TYPE_PASSWORD;
  expect("secure-only password can be deleted",
         seedkeeper_can_delete(&header));
}

static void test_descriptor_secret(void) {
  uint8_t body[8];
  size_t n = seedkeeper_secret_encode_descriptor("ab", body, sizeof(body));
  const uint8_t *text = NULL;
  size_t tlen = 0;
  expect("descriptor encode", n == 4 && body[0] == 0x00 && body[1] == 0x02 &&
                                  body[2] == 'a' && body[3] == 'b');
  expect("descriptor decode",
         seedkeeper_descriptor_decode(body, n, &text, &tlen) ==
                 SEEDKEEPER_DECODE_OK &&
             tlen == 2 && text[0] == 'a' && text[1] == 'b');
  expect("empty descriptor rejected",
         seedkeeper_secret_encode_descriptor("", body, sizeof(body)) == 0);
  expect("null descriptor rejected",
         seedkeeper_secret_encode_descriptor(NULL, body, sizeof(body)) == 0);

  const uint8_t short_body[] = {0x00, 0x02, 'a'};
  expect("short descriptor rejected",
         seedkeeper_descriptor_decode(short_body, sizeof(short_body), &text,
                                      &tlen) == SEEDKEEPER_DECODE_MALFORMED);
  const uint8_t nul_body[] = {0x00, 0x03, 'a', 0x00, 'b'};
  expect("descriptor nul rejected",
         seedkeeper_descriptor_decode(nul_body, sizeof(nul_body), &text,
                                      &tlen) == SEEDKEEPER_DECODE_MALFORMED);
  const uint8_t extra[] = {0x00, 0x01, 'a', 'b'};
  expect("descriptor tail rejected",
         seedkeeper_descriptor_decode(extra, sizeof(extra), &text, &tlen) ==
             SEEDKEEPER_DECODE_MALFORMED);

  seedkeeper_header_t header = {0};
  header.type = SEEDKEEPER_TYPE_DESCRIPTOR;
  header.export_rights = SEEDKEEPER_EXPORT_ALLOWED;
  expect("descriptor can load", seedkeeper_can_descriptor(&header));
  header.export_rights = 0x02;
  expect("secure-only descriptor stays", !seedkeeper_can_descriptor(&header));
  header.type = SEEDKEEPER_TYPE_BIP39;
  header.export_rights = SEEDKEEPER_EXPORT_ALLOWED;
  expect("mnemonic is not a descriptor", !seedkeeper_can_descriptor(&header));
  expect("null descriptor header", !seedkeeper_can_descriptor(NULL));
}

/* 30 len | 02 lr r | 02 ls s, with r and s filled with `rb` and `sb`. */
static size_t make_der(uint8_t *out, size_t lr, uint8_t rb, size_t ls,
                       uint8_t sb) {
  size_t i = 0;
  out[i++] = 0x30;
  out[i++] = (uint8_t)(4 + lr + ls);
  out[i++] = 0x02;
  out[i++] = (uint8_t)lr;
  for (size_t k = 0; k < lr; k++)
    out[i++] = (lr == 33 && k == 0) ? 0x00 : rb;
  out[i++] = 0x02;
  out[i++] = (uint8_t)ls;
  for (size_t k = 0; k < ls; k++)
    out[i++] = (ls == 33 && k == 0) ? 0x00 : sb;
  return i;
}

static int all_bytes(const uint8_t *p, size_t n, uint8_t v) {
  for (size_t i = 0; i < n; i++) {
    if (p[i] != v)
      return 0;
  }
  return 1;
}

static void test_der_rs(void) {
  uint8_t sig[80];
  uint8_t r[32], s[32];
  size_t n = make_der(sig, 32, 0x11, 32, 0x22);
  expect("der 32/32", seedkeeper_sc_der_rs(sig, n, r, s) &&
                          all_bytes(r, 32, 0x11) && all_bytes(s, 32, 0x22));

  n = make_der(sig, 33, 0x81, 32, 0x22);
  expect("der high r", seedkeeper_sc_der_rs(sig, n, r, s) &&
                           all_bytes(r, 32, 0x81) && all_bytes(s, 32, 0x22));

  /* A high s comes as 33 bytes with a 0x00 sign byte. */
  n = make_der(sig, 32, 0x11, 33, 0x82);
  expect("der high s", seedkeeper_sc_der_rs(sig, n, r, s) &&
                           all_bytes(r, 32, 0x11) && all_bytes(s, 32, 0x82));

  n = make_der(sig, 33, 0x81, 33, 0x82);
  expect("der high r and s", seedkeeper_sc_der_rs(sig, n, r, s) &&
                                 all_bytes(r, 32, 0x81) &&
                                 all_bytes(s, 32, 0x82));

  n = make_der(sig, 31, 0x11, 31, 0x22);
  expect("der short r and s",
         seedkeeper_sc_der_rs(sig, n, r, s) && r[0] == 0 &&
             all_bytes(r + 1, 31, 0x11) && s[0] == 0 &&
             all_bytes(s + 1, 31, 0x22));

  n = make_der(sig, 32, 0x11, 33, 0x82);
  sig[6 + 32] = 0x01;
  expect("der 33-byte s without sign byte",
         !seedkeeper_sc_der_rs(sig, n, r, s));

  n = make_der(sig, 33, 0x81, 32, 0x22);
  sig[4] = 0x01;
  expect("der 33-byte r without sign byte",
         !seedkeeper_sc_der_rs(sig, n, r, s));

  n = make_der(sig, 32, 0x11, 32, 0x22);
  expect("der truncated", !seedkeeper_sc_der_rs(sig, n - 1, r, s));
}

int main(void) {
  test_slot_status_frame();
  test_nak_and_prefix();
  test_bad_lrc();
  test_xfr_roundtrip();
  test_seedkeeper();
  test_t1();
  test_secure_channel();
  test_der_rs();
  test_secret_decode();
  test_secret_import();
  test_password_decode();
  test_descriptor_secret();
  printf("%d passed, %d failed\n", passed, failed);
  return failed ? 1 : 0;
}
