/*
 * Pro Micro (ATmega32u4) composite HID receiver
 *
 * Receives raw binary frames from the Pico host over Serial1 (UART pins
 * 0/1, 115200) and re-emits them to the PC as a composite USB HID device:
 *
 *   keyboard  - standard 6-key + modifiers (pass-through of keycodes)
 *   mouse     - buttons, 16-bit relative X/Y, wheel, pan
 *   consumer  - volume up/down + mute (0xE9 / 0xEA / 0xE2), edge-triggered
 *
 * Input protocol (from hid_host_keyboard.ino), no ASCII text framing:
 *   0x81 <inst> <len> <b0> <b1> ... <b{len-1}>
 *
 *   inst 0          : keyboard 8-byte report [mod res k0..k5]
 *   inst 2, id 0x03 : mouse    03 <btn> <Xlo> <Xhi> <Ylo> <Yhi> <wheel> <pan>
 *   inst 2, id 0x02 : consumer 02 <B0..B1..B2> (18-bit bitmap; bits 8/9/10)
 *   inst 1          : vendor HID, ignored
 *   inst 2, id 0x01 : system control, ignored
 *   inst 2, id 0x04 : second keyboard, ignored
 *
 * Parser state machine:
 *   WAIT_STX -> 0x81 -> WAIT_INST -> WAIT_LEN -> LEN bytes -> dispatch
 *   Any byte mismatch returns to WAIT_STX (resync). The loop never blocks:
 *   the STM32u4 Serial1 RX ring is only 16 bytes, so a delay() in the drain
 *   would drop bursty mouse/keyboard reports.
 *
 * Parsed events are printed to ttyACM0 (CDC); the LED toggles only on a
 * completed, parsed event (parse-success indicator), never per raw byte.
 *
 * Board:   Arduino Leonardo (or SparkFun Pro Micro)
 * Library: "HID-Project" by Nico Hood (Library Manager) - replaces the core
 *          HID with a composite of whichever classes you begin().
 *
 * The Pro Micro is powered from its own USB port (the PC it presents to);
 * only GND is shared with the Pico. Wire Pico GPIO0 (TX) -> this RX (pin 0).
 */

#include "HID-Project.h"

static const uint32_t BAUD = 115200;

// ---------------------------------------------------------------------
// OTP (TOTP typing). Only the receiver on the computer that needs the OTP
// sets OTP_ENABLED=1; the other receiver keeps 0 = stock behavior.
//   OTP_DIGITS   - token length typed (6 = RFC standard)
//   OTP_DEFAULT_SECRET_B32 - fallback secret if EEPROM is unprovisioned
//                            (RFC 4648 base32, A-Z2-7)
//   Provision at runtime with  s <base32>  over ttyACM0 (CDC).
//   Boot self-test verifies RFC 6238 vectors when OTP_SELFTEST=1.
// ---------------------------------------------------------------------
#define OTP_ENABLED 1
#define OTP_DIGITS 6
#define OTP_DEFAULT_SECRET_B32 "JBSWY3DPEHPK3PXP"
#define OTP_SELFTEST 1

#include <string.h>
#if OTP_ENABLED
#include <EEPROM.h>
#include "totp.h"

// --- secret storage (EEPROM: 'OTP' magic + len + raw bytes) ---
static uint8_t otp_secret[20];
static uint8_t otp_secret_len = 0;

static void otp_use_default_secret(void) {
  otp_secret_len = (uint8_t)base32_decode(OTP_DEFAULT_SECRET_B32,
                     strlen(OTP_DEFAULT_SECRET_B32), otp_secret, sizeof(otp_secret));
}

static void otp_load_secret(void) {
  if (EEPROM.read(0) == 'O' && EEPROM.read(1) == 'T' && EEPROM.read(2) == 'P') {
    uint8_t n = EEPROM.read(3);
    if (n >= 1 && n <= sizeof(otp_secret)) {
      for (uint8_t i = 0; i < n; i++) otp_secret[i] = EEPROM.read(4 + i);
      otp_secret_len = n;
      Serial.print("OTP secret: EEPROM (");
      Serial.print(otp_secret_len);
      Serial.println(" bytes)");
      return;
    }
  }
  otp_use_default_secret();
  Serial.print("OTP secret: default (");
  Serial.print(otp_secret_len);
  Serial.println(" bytes)");
}

static void otp_store_secret(const uint8_t *bytes, uint8_t n) {
  EEPROM.write(0, 'O'); EEPROM.write(1, 'T'); EEPROM.write(2, 'P');
  EEPROM.write(3, n);
  for (uint8_t i = 0; i < n; i++) EEPROM.write(4 + i, bytes[i]);
  for (uint8_t i = n; i < sizeof(otp_secret); i++) EEPROM.write(4 + i, 0);
  memcpy(otp_secret, bytes, n);
  otp_secret_len = n;
  Serial.print("OTP secret: provisioned (");
  Serial.print(n);
  Serial.println(" bytes)");
}

// --- CDC command line:  s <base32>  -> provision secret to EEPROM ---
static char otp_cmd[80];
static uint8_t otp_cmd_len = 0;

static void otp_service_cdc(void) {
  while (Serial.available()) {
    char ch = (char)Serial.read();
    if (ch == '\n' || ch == '\r') {
      if (otp_cmd_len > 0) {
        otp_cmd[otp_cmd_len] = '\0';
        char *p = otp_cmd + 1;               // skip command char
        while (*p == ' ' || *p == '\t') p++;
        uint8_t buf[sizeof(otp_secret)];
        size_t n = base32_decode(p, strlen(p), buf, sizeof(buf));
        if (n >= 1 && n <= sizeof(otp_secret)) {
          otp_store_secret(buf, (uint8_t)n);
        } else {
          Serial.println("OTP secret: BAD base32");
        }
      }
      otp_cmd_len = 0;
    } else if (otp_cmd_len < sizeof(otp_cmd) - 1) {
      otp_cmd[otp_cmd_len++] = ch;
    }
  }
}

// --- RFC 6238 known-answer self-test (SHA-1, 8-digit vectors) ---
static void otp_selftest(void) {
  const uint8_t secret[] = "12345678901234567890";
  struct { uint64_t t; uint32_t want; } vec[] = {
    { 59ULL,        94287082u },
    { 1111111109ULL,  7081804u },
    { 1111111111ULL, 14050471u },
    { 1234567890ULL, 89005924u },
    { 2000000000ULL, 69279037u },
    { 20000000000ULL, 65353130u },
  };
  bool ok = true;
  for (uint8_t i = 0; i < sizeof(vec) / sizeof(vec[0]); i++) {
    uint32_t v = totp(secret, sizeof(secret) - 1, vec[i].t, 8);
    if (v != vec[i].want) {
      ok = false;
      Serial.print("OTP SELFTEST FAIL counter=");
      Serial.println((unsigned long)(vec[i].t / 30));
    }
  }
  Serial.println(ok ? "OTP SELFTEST PASS" : "OTP SELFTEST FAIL");
}
#endif

// ---------------------------------------------------------------------
// Binary frame parser (Serial1, 8N1)
// ---------------------------------------------------------------------
enum { S_WAIT_STX, S_WAIT_INST, S_WAIT_LEN, S_DATA };

static uint8_t fsm_state = S_WAIT_STX;
static uint8_t g_inst;            // dispatch key (HID instance)
static uint8_t g_len;             // expected payload length
static uint8_t g_rep[64];         // raw report bytes
static uint8_t g_nb;              // payload bytes received so far

// ---------------------------------------------------------------------
// Keyboard (instance 0): 8 bytes  [mod 0, reserved, k0..k5]
//     Modifier bits: b0=LCtrl  b1=LShift  b2=LAlt  b3=LGUI
//                    b4=RCtrl  b5=RShift  b6=RAlt  b7=RGUI
//     Keyboard codes: HID usage codes, 0x04..0xE7, 0=unused.
//     Delta: press newly-appeared codes, release vanishing codes.
// ---------------------------------------------------------------------
static uint8_t prev_kb_mod = 0;
static uint8_t prev_kb_keys[6];

static void emit_kb(void) {
  uint8_t mod = g_rep[0];              // [0] modifier, [1] reserved
  const uint8_t *keys = g_rep + 2;     // [2..7] = k0..k5

  // --- modifier deltas ---
  for (uint8_t b = 0; b < 8; b++) {
    bool cur  = (mod   >> b) & 1;
    bool prev = (prev_kb_mod >> b) & 1;
    if ( cur && !prev) Keyboard.press((KeyboardKeycode)(0xE0 + b));
    if (!cur &&  prev) Keyboard.release((KeyboardKeycode)(0xE0 + b));
  }
  prev_kb_mod = mod;

  // --- keycodes: collect current set, compute deltas against prev ---
  uint8_t cur_keys[6];
  memcpy(cur_keys, keys, 6);

  // release any prev keycode not present in cur_keys
  for (uint8_t i = 0; i < 6; i++) {
    if (prev_kb_keys[i] == 0) continue;
    bool found = false;
    for (uint8_t j = 0; j < 6; j++) {
      if (cur_keys[j] == prev_kb_keys[i]) { found = true; break; }
    }
    if (!found) Keyboard.release((KeyboardKeycode)prev_kb_keys[i]);
  }
  // press any cur keycode not present in prev_kb_keys
  for (uint8_t i = 0; i < 6; i++) {
    if (cur_keys[i] == 0) continue;
    bool found = false;
    for (uint8_t j = 0; j < 6; j++) {
      if (prev_kb_keys[j] == cur_keys[i]) { found = true; break; }
    }
    if (!found) Keyboard.press((KeyboardKeycode)cur_keys[i]);
  }
  memcpy(prev_kb_keys, cur_keys, 6);
}

// ---------------------------------------------------------------------
// Mouse (instance 2, report id 0x03): 03 btn Xlo Xhi Ylo Yhi wheel pan
//     16-bit signed LE X/Y; buttons bit0=L bit1=R bit2=M.
// ---------------------------------------------------------------------
static uint8_t prev_mouse_btn = 0;

static void emit_mouse(void) {
  uint8_t btn = g_rep[1];

  int16_t dx = (int16_t)((uint16_t)g_rep[2] | ((uint16_t)g_rep[3] << 8));
  int16_t dy = (int16_t)((uint16_t)g_rep[4] | ((uint16_t)g_rep[5] << 8));
  int8_t  wheel = (int8_t)g_rep[6];
  // g_rep[7] is horizontal pan; HID-Project's Mouse.move has no pan arg, ignore.

  if (dx || dy || wheel) Mouse.move(dx, dy, wheel);

  for (uint8_t b = 0; b < 3; b++) {
    uint8_t mask = (uint8_t)(1 << b);
    if ((btn & mask) && !(prev_mouse_btn & mask)) Mouse.press(mask);
    if (!(btn & mask) && (prev_mouse_btn & mask)) Mouse.release(mask);
  }
  prev_mouse_btn = btn;
}

// ---------------------------------------------------------------------
// Consumer (instance 2, report id 0x02): 02 00 B0 B1 B2
//     18-bit bitmap at byte offset 1, little-endian.
//       bit 8  -> 0xE2  MUTE
//       bit 9  -> 0xEA  VOLUME DOWN
//       bit 10 -> 0xE9  VOLUME UP
//     Edge-triggered press/release so auto-repeat works while held.
// ---------------------------------------------------------------------
static uint8_t prev_cons = 0;          // 3 state bits: bit0=MUTE 1=VOL- 2=VOL+

static void emit_consumer(void) {
  uint32_t bm = (uint32_t)g_rep[1] | ((uint32_t)g_rep[2] << 8) | ((uint32_t)g_rep[3] << 16);
  uint8_t cur = 0;
  if (bm & (1u << 8))  cur |= (1 << 0);   // mute
  if (bm & (1u << 9))  cur |= (1 << 1);   // volume down
  if (bm & (1u << 10)) cur |= (1 << 2);   // volume up

  for (uint8_t b = 0; b < 3; b++) {
    uint8_t mask = (uint8_t)(1 << b);
    uint16_t usage = (b == 0) ? 0xE2 : (b == 1) ? 0xEA : 0xE9;
    if ((cur & mask) && !(prev_cons & mask)) Consumer.press(usage);
    if (!(cur & mask) && (prev_cons & mask)) Consumer.release(usage);
  }
  prev_cons = cur;
}

// ---------------------------------------------------------------------
// Parsed-event print helpers (ttyACM0, in len bytes). Never raw bytes.
// ---------------------------------------------------------------------
static void print_hex(uint8_t v) {
  if (v < 0x10) Serial.print('0');
  Serial.print(v, HEX);
}

static void print_kb_event(void) {
  Serial.print("KB mod=");
  print_hex(g_rep[0]);
  Serial.print(" keys=[");
  for (uint8_t i = 0; i < 6; i++) {
    if (i) Serial.print(',');
    print_hex(g_rep[2 + i]);
  }
  Serial.println(']');
}

static void print_mouse_event(void) {
  int16_t dx = (int16_t)((uint16_t)g_rep[2] | ((uint16_t)g_rep[3] << 8));
  int16_t dy = (int16_t)((uint16_t)g_rep[4] | ((uint16_t)g_rep[5] << 8));
  Serial.print("MS btn=");
  Serial.print(g_rep[1]);
  Serial.print(" dx=");
  Serial.print(dx);
  Serial.print(" dy=");
  Serial.println(dy);
}

static void print_consumer_event(void) {
  uint32_t bm = (uint32_t)g_rep[1] | ((uint32_t)g_rep[2] << 8) | ((uint32_t)g_rep[3] << 16);
  Serial.print("CONS mask=");
  Serial.println(bm & 0x3FFFFu, HEX);
}

// ---------------------------------------------------------------------
// Dispatch one completed frame: emit on the composite HID, then report the
// parsed event on CDC and toggle the LED (parse-success indicator).
// ---------------------------------------------------------------------
static void dispatch(void) {
  switch (g_inst) {
    case 0:                          // keyboard
      if (g_len >= 8) {
        emit_kb();
        print_kb_event();
      }
      break;
    case 2:                          // mouse / consumer / (system/2nd kb ignored)
      if (g_len >= 1 && g_rep[0] == 0x03 && g_len >= 8) {
        emit_mouse();
        print_mouse_event();
      } else if (g_len >= 1 && g_rep[0] == 0x02 && g_len >= 5) {
        emit_consumer();
        print_consumer_event();
      }
      break;
    default:                         // vendor/system HID, ignored
      break;
  }
  digitalWrite(LED_BUILTIN, !digitalRead(LED_BUILTIN));
}

// ---------------------------------------------------------------------
// setup / loop
// ---------------------------------------------------------------------
void setup() {
  pinMode(LED_BUILTIN, OUTPUT);

  // Composite HID: keyboard + mouse + consumer (volume/mute).
  Keyboard.begin();
  Mouse.begin();
  Consumer.begin();

#if OTP_ENABLED
  otp_load_secret();
#if OTP_SELFTEST
  otp_selftest();
#endif
#endif

  Serial1.begin(BAUD);   // UART pins 0/1 <- Pico GPIO0
}

void loop() {
#if OTP_ENABLED
  // Provisioning commands on ttyACM0 (CDC). Non-blocking.
  otp_service_cdc();
#endif

  // Non-blocking drain; see the ring-buffer note above.
  while (Serial1.available()) {
    uint8_t c = Serial1.read();

    switch (fsm_state) {
      case S_WAIT_STX:
        if (c == 0x81) fsm_state = S_WAIT_INST;
        break;

      case S_WAIT_INST:
        g_inst = c;
        fsm_state = S_WAIT_LEN;
        break;

      case S_WAIT_LEN:
        g_len = c;
        if (g_len == 0 || g_len > sizeof(g_rep)) {
          fsm_state = S_WAIT_STX;    // bad length; resync
          break;
        }
        g_nb = 0;
        fsm_state = S_DATA;
        break;

      case S_DATA:
        g_rep[g_nb++] = c;
        if (g_nb >= g_len) {
          dispatch();
          fsm_state = S_WAIT_STX;
        }
        break;
    }
  }
}