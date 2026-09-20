/*
 * totp.h - RFC 4226/6238 time-based one-time passwords (HMAC-SHA1)
 *
 * Self-contained, no Arduino dependencies, so the same source compiles for
 * the host test harness and the ATmega32u4 sketch.
 *
 *   base32_decode()  - RFC 4648 base32 -> raw secret bytes
 *   hmac_sha1()      - raw HMAC-SHA1 (20-byte digest)
 *   hotp()           - RFC 4226: counter-based HMAC pad
 *   totp()           - RFC 6238: 30 s time step, decimal digits
 */

#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Decodes a base32 string (RFC 4648 alphabet A-Z2-7, optional '=' padding).
// Returns number of bytes written, or 0 on decode failure.
size_t base32_decode(const char *in, size_t in_len,
                     uint8_t *out, size_t out_cap);

// HMAC-SHA1 of key/msg. Writes 20 bytes to out.
void hmac_sha1(const uint8_t *key, size_t key_len,
               const uint8_t *msg, size_t msg_len,
               uint8_t out[20]);

// RFC 4226 counter-mode HOTP. msg = 8-byte big-endian counter.
// Returns the truncated code modulo 10^digits (digits 1..8).
uint32_t hotp(const uint8_t *secret, size_t secret_len,
              uint64_t counter, uint8_t digits);

// RFC 6238 TOTP. epoch_sec is unix time; step is fixed at 30 s.
uint32_t totp(const uint8_t *secret, size_t secret_len,
              uint64_t epoch_sec, uint8_t digits);

#ifdef __cplusplus
}
#endif