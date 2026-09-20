/*
 * totp.cpp - RFC 4226/6238 one-time passwords, HMAC-SHA1
 *
 * Streaming SHA-1 context used internally; public API is in totp.h.
 * CPU/memory budget on ATmega32u4 is small (SHA-1 fits easily on 2.5 KB SRAM).
 */

#include "totp.h"
#include <string.h>

// ---------------------------------------------------------------------
// SHA-1 (FIPS 180-4)
// ---------------------------------------------------------------------

typedef struct {
  uint32_t h[5];
  uint64_t len_bits;      // total message length in bits
  uint8_t  buf[64];
  uint8_t  buf_len;
} sha1_ctx;

static inline uint32_t rol(uint32_t v, int n) {
  return (v << n) | (v >> (32 - n));
}

static void sha1_transform(sha1_ctx *c) {
  static const uint32_t K[4] = { 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6 };
  uint32_t w[80];
  for (int i = 0; i < 16; i++) {
    w[i] = ((uint32_t)c->buf[i * 4] << 24)
         | ((uint32_t)c->buf[i * 4 + 1] << 16)
         | ((uint32_t)c->buf[i * 4 + 2] << 8)
         |  (uint32_t)c->buf[i * 4 + 3];
  }
  for (int i = 16; i < 80; i++) {
    w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
  }

  uint32_t a = c->h[0], b = c->h[1], e2 = c->h[2], d = c->h[3], e = c->h[4];
  for (int i = 0; i < 80; i++) {
    uint32_t f, k;
    if (i < 20)       { f = (b & e2) | (~b & d);        k = K[0]; }
    else if (i < 40)  { f = b ^ e2 ^ d;                 k = K[1]; }
    else if (i < 60)  { f = (b & e2) | (b & d) | (e2 & d); k = K[2]; }
    else              { f = b ^ e2 ^ d;                 k = K[3]; }
    uint32_t tmp = rol(a, 5) + f + e + k + w[i];
    e = d; d = e2; e2 = rol(b, 30); b = a; a = tmp;
  }
  c->h[0] += a; c->h[1] += b; c->h[2] += e2; c->h[3] += d; c->h[4] += e;
}

static void sha1_init(sha1_ctx *c) {
  c->h[0] = 0x67452301; c->h[1] = 0xEFCDAB89;
  c->h[2] = 0x98BADCFE; c->h[3] = 0x10325476; c->h[4] = 0xC3D2E1F0;
  c->len_bits = 0;
  c->buf_len = 0;
}

static void sha1_update(sha1_ctx *c, const uint8_t *data, size_t n) {
  while (n) {
    size_t take = 64 - c->buf_len;
    if (take > n) take = n;
    memcpy(c->buf + c->buf_len, data, take);
    c->buf_len += (uint8_t)take;
    data += take;
    n -= take;
    c->len_bits += (uint64_t)take * 8;
    if (c->buf_len == 64) {
      sha1_transform(c);
      c->buf_len = 0;
    }
  }
}

static void sha1_final(sha1_ctx *c, uint8_t out[20]) {
  uint64_t bits = c->len_bits;
  uint8_t pad = 0x80;
  sha1_update(c, &pad, 1);
  uint8_t zero = 0;
  while (c->buf_len != 56) sha1_update(c, &zero, 1);
  uint8_t lenb[8];
  for (int i = 0; i < 8; i++) lenb[i] = (uint8_t)(bits >> (56 - i * 8));
  sha1_update(c, lenb, 8);
  for (int i = 0; i < 5; i++) {
    out[i * 4 + 0] = (uint8_t)(c->h[i] >> 24);
    out[i * 4 + 1] = (uint8_t)(c->h[i] >> 16);
    out[i * 4 + 2] = (uint8_t)(c->h[i] >> 8);
    out[i * 4 + 3] = (uint8_t)(c->h[i]);
  }
}

// ---------------------------------------------------------------------
// HMAC-SHA1 (RFC 2104)
// ---------------------------------------------------------------------

void hmac_sha1(const uint8_t *key, size_t key_len,
               const uint8_t *msg, size_t msg_len,
               uint8_t out[20]) {
  uint8_t k[64];
  if (key_len > 64) {
    sha1_ctx kc;
    sha1_init(&kc);
    sha1_update(&kc, key, key_len);
    sha1_final(&kc, k);
    memset(k + 20, 0, 64 - 20);
  } else {
    memcpy(k, key, key_len);
    memset(k + key_len, 0, 64 - key_len);
  }

  uint8_t ipad[64], opad[64];
  for (int i = 0; i < 64; i++) {
    ipad[i] = k[i] ^ 0x36;
    opad[i] = k[i] ^ 0x5C;
  }

  sha1_ctx c;
  uint8_t inner[20];
  sha1_init(&c);
  sha1_update(&c, ipad, 64);
  sha1_update(&c, msg, msg_len);
  sha1_final(&c, inner);

  sha1_init(&c);
  sha1_update(&c, opad, 64);
  sha1_update(&c, inner, 20);
  sha1_final(&c, out);
}

// ---------------------------------------------------------------------
// Base32 (RFC 4648)
// ---------------------------------------------------------------------

static int8_t base32_val(char c) {
  if (c >= 'A' && c <= 'Z') return (int8_t)(c - 'A');
  if (c >= 'a' && c <= 'z') return (int8_t)(c - 'a');
  if (c >= '2' && c <= '7') return (int8_t)(c - '2' + 26);
  return -1;
}

size_t base32_decode(const char *in, size_t in_len,
                     uint8_t *out, size_t out_cap) {
  size_t o = 0;
  uint32_t acc = 0;
  int bits = 0;
  for (size_t i = 0; i < in_len; i++) {
    char c = in[i];
    if (c == '=') break;                    // padding terminates input
    if (c == ' ' || c == '\t' || c == '\n' || c == '\r') continue;
    int8_t v = base32_val(c);
    if (v < 0) return 0;
    acc = (acc << 5) | (uint32_t)v;
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      if (o >= out_cap) return 0;
      out[o++] = (uint8_t)((acc >> bits) & 0xFF);
    }
  }
  return o;
}

// ---------------------------------------------------------------------
// HOTP / TOTP (RFC 4226 / RFC 6238)
// ---------------------------------------------------------------------

uint32_t hotp(const uint8_t *secret, size_t secret_len,
              uint64_t counter, uint8_t digits) {
  uint8_t msg[8];
  for (int i = 0; i < 8; i++) msg[i] = (uint8_t)(counter >> (56 - i * 8));

  uint8_t mac[20];
  hmac_sha1(secret, secret_len, msg, 8, mac);

  uint32_t offset = mac[19] & 0x0F;
  uint32_t bin = ((uint32_t)(mac[offset] & 0x7F) << 24)
               | ((uint32_t)mac[offset + 1] << 16)
               | ((uint32_t)mac[offset + 2] << 8)
               |  (uint32_t)mac[offset + 3];

  uint32_t mod = 1;
  for (uint8_t d = 0; d < digits; d++) mod *= 10;
  return bin % mod;
}

uint32_t totp(const uint8_t *secret, size_t secret_len,
              uint64_t epoch_sec, uint8_t digits) {
  return hotp(secret, secret_len, epoch_sec / 30, digits);
}