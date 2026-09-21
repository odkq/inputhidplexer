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
// OTP (HOTP typing). Only the receiver on the computer that needs the OTP
// sets OTP_ENABLED=1; the other receiver keeps 0 = stock behavior.
//   OTP_DIGITS   - token length typed (6 = RFC standard)
//   OTP_SECRET_B32 - the secret, baked into firmware Flash at compile time
//                    (RFC 4648 base32, A-Z2-7). WORTH REMEMBERING: anyone
//                    who can reflash/read the chip can get it, and there is
//                    NO runtime provisioning - set it before flashing.
//   OTP_PREAMBLE - text typed BEFORE the digits (e.g. "ga:"), "" = none.
//   Trigger on this receiver: PrintScreen types the HOTP digits;
//   Shift+PrintScreen types only the preamble. Both the keycode and the
//   Shift modifier are swallowed (never forwarded to the PC), and the code
//   is typed with a non-blocking state machine.
//   HOTP (RFC 4226): counter-based. The 32-bit counter only ever increments
//   and is persisted to EEPROM after every typed code; there is NO clock and
//   NO time sync. Server desync is repaired server-side per RFC 4226 7.4
//   look-ahead resync.
//   Boot self-test verifies RFC 6238 vectors when OTP_SELFTEST=1.
// ---------------------------------------------------------------------
#define OTP_ENABLED 1
#define OTP_DIGITS 6
#define OTP_SECRET_B32 "JBSWY3DPEHPK3PXP"  // Change with your HOTP secret
#define OTP_PREAMBLE "preamb"              //  Something that will be printed with Shift+PrintScr
                                 // "" = none. ASCII only, US layout, max 18 chars.
#define OTP_SELFTEST 1

#include <string.h>
#if OTP_ENABLED
#include <EEPROM.h>
#include <avr/pgmspace.h>
#include "totp.h"

// --- HOTP (RFC 4226) counter state. No clock, no time sync, no RTC, no
// escape hatch: the counter ONLY ever increments, and after each typed
// code it is advanced + persisted to EEPROM. Server desync is repaired
// server-side per RFC 4226 7.4 (the verifier tries successive counters in
// a look-ahead window and re-syncs on the match); the device just goes up.
static uint32_t otp_counter = 0;            // current HOTP counter
static const uint16_t HOTP_CTR_EEPROM_ADDR = 24;   // after secret (0..23)
static const uint8_t  HOTP_CTR_EEPROM_LEN = 4;

// --- secret: baked into firmware Flash, decoded into RAM once at boot.
//     No runtime provisioning; there is no read-back from the MCU. ---
static uint8_t otp_secret[20];
static uint8_t otp_secret_len = 0;

static void otp_load_secret(void) {
  static const char b32[] PROGMEM = OTP_SECRET_B32;
  char buf[sizeof(b32)];
  memcpy_P(buf, b32, sizeof(b32));
  otp_secret_len = (uint8_t)base32_decode(buf, strlen(buf), otp_secret, sizeof(otp_secret));
  Serial.print("OTP secret: flash (");
  Serial.print(otp_secret_len);
  Serial.println(" bytes)");
}

// --- CDC command line: ignored. HOTP has no clock and no provisioning; the
//     counter only ever increments. Lines the daemon may send (e.g. the old
//     't <epoch_s>' time-sync) are drained here and ignored. ---
static char otp_cmd[80];
static uint8_t otp_cmd_len = 0;

static void otp_service_cdc(void) {
  while (Serial.available()) {
    char ch = (char)Serial.read();
    if (ch == '\n' || ch == '\r') {
      if (otp_cmd_len > 0) {
        otp_cmd[otp_cmd_len] = '\0';
        Serial.println("OTP: no commands (HOTP has no clock)");
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

// --- non-blocking typing state machine (never delay() in the loop) ---
enum { OTP_IDLE, OTP_ARM, OTP_HELD, OTP_GAP };
static const uint32_t OTP_HOLD_MS = 25;             // press duration per char
static const uint32_t OTP_GAP_MS  = 10;             // pause between chars

typedef struct { uint8_t key; uint8_t shift; } otp_stroke_t;  // HID usage + shift bit
static uint8_t otp_state = OTP_IDLE;
static otp_stroke_t otp_strokes[24];                 // preamble chars + digits
static uint8_t otp_ndigits = 0;                      // total strokes to type
static uint8_t otp_digit_idx = 0;
static uint32_t otp_step_ms = 0;                     // when the phase started
static bool     otp_type_digits = false;             // digit run (vs preamble-only)

// ASCII char -> (HID usage, whether Shift is needed). US layout.
static uint8_t otp_chr_keycode(uint8_t c, bool *shift) {
  if (c >= '0' && c <= '9') return (uint8_t)(0x1E + (c - '0'));
  if (c >= 'a' && c <= 'z') return (uint8_t)(0x04 + (c - 'a'));
  if (c >= 'A' && c <= 'Z') { *shift = true; return (uint8_t)(0x04 + (c - 'A')); }
  switch (c) {
    case ' ': *shift = false; return 0x2C;
    case '!': *shift = true;  return 0x1E;
    case '"': *shift = true;  return 0x34;
    case '#': *shift = true;  return 0x20;
    case '$': *shift = true;  return 0x21;
    case '%': *shift = true;  return 0x22;
    case '&': *shift = true;  return 0x24;
    case '\'': *shift = false; return 0x34;
    case '(': *shift = true;  return 0x26;
    case ')': *shift = true;  return 0x27;
    case '*': *shift = true;  return 0x25;
    case '+': *shift = true;  return 0x2E;
    case ',': *shift = false; return 0x36;
    case '-': *shift = false; return 0x2D;
    case '.': *shift = false; return 0x37;
    case '/': *shift = false; return 0x38;
    case ':': *shift = true;  return 0x33;
    case ';': *shift = false; return 0x33;
    case '<': *shift = true;  return 0x36;
    case '=': *shift = false; return 0x2E;
    case '>': *shift = true;  return 0x37;
    case '?': *shift = true;  return 0x38;
    case '@': *shift = true;  return 0x1F;
    case '[': *shift = false; return 0x2F;
    case '\\': *shift = false; return 0x31;
    case ']': *shift = false; return 0x30;
    case '^': *shift = true;  return 0x23;
    case '_': *shift = true;  return 0x2D;
    case '`': *shift = false; return 0x35;
    case '{': *shift = true;  return 0x2F;
    case '|': *shift = true;  return 0x31;
    case '}': *shift = true;  return 0x30;
    case '~': *shift = true;  return 0x35;
    default:                  return 0;              // unsupported char
  }
}

static uint8_t otp_keycode_for_digit(uint8_t d) {   // 0..9 -> HID usage
  if (d == 0) return 0x27;                          // '0'
  return (uint8_t)(0x1E + (d - 1));                 // '1'..'9' = 0x1E..0x26
}

#define OTP_RET_SHIFT  0xE1   // HID usage: left Shift
#define OTP_RET_LCTRL  0xE0   // HID usage: left Ctrl
#define OTP_RET_RCTRL  0xE4   // HID usage: right Ctrl
#define OTP_RET_RSHIFT 0xE5   // HID usage: right Shift

static void otp_press_stroke(uint8_t i) {
  if (otp_strokes[i].shift) Keyboard.press((KeyboardKeycode)OTP_RET_SHIFT);
  Keyboard.press((KeyboardKeycode)otp_strokes[i].key);
}

static void otp_release_stroke(uint8_t i) {
  Keyboard.release((KeyboardKeycode)otp_strokes[i].key);
  if (otp_strokes[i].shift) Keyboard.release((KeyboardKeycode)OTP_RET_SHIFT);
}

// digits -> if 0 print the preamble, otherwise print the digits
static bool otp_trigger(int digits) {
  if (otp_state != OTP_IDLE) {
    Serial.println("OTP busy");
    return false;
  }
  uint32_t code = hotp(otp_secret, otp_secret_len, otp_counter, OTP_DIGITS);

  // Build the full stroke list: preamble (OTP_PREAMBLE) or
  // digits. Each stroke carries its own Shift flag, so punctuation in the
  // preamble types cleanly (US layout).
  uint8_t n = 0;
  otp_type_digits = (digits != 0);
  if (!digits) {
    for (const char *p = OTP_PREAMBLE; *p && n < sizeof(otp_strokes)/sizeof(otp_strokes[0]); p++) {
      bool shift = false;
      uint8_t usage = otp_chr_keycode((uint8_t)*p, &shift);
      if (usage) {
        otp_strokes[n].key = usage;
        otp_strokes[n].shift = shift ? 1 : 0;
        n++;
      }
    }
    otp_ndigits = (uint8_t)(n);
  } else {
    for (uint8_t i = OTP_DIGITS; i-- > 0;) {
      otp_strokes[n + i].key = otp_keycode_for_digit((uint8_t)(code % 10));
      otp_strokes[n + i].shift = 0;
      code /= 10;
    }
    otp_ndigits = (uint8_t)(OTP_DIGITS);
  }

  otp_digit_idx = 0;
  // A trigger modifier may already have been forwarded to the PC (e.g. a
  // frame with just Shift before the PrintScreen). Release all trigger mods
  // NOW so the first stroke is never pressed while the OS still holds one.
  Keyboard.release((KeyboardKeycode)OTP_RET_SHIFT);
  Keyboard.release((KeyboardKeycode)OTP_RET_RSHIFT);
  Keyboard.release((KeyboardKeycode)OTP_RET_LCTRL);
  Keyboard.release((KeyboardKeycode)OTP_RET_RCTRL);
  otp_state = OTP_ARM;              // press stroke 0 on the next service() tick,
  otp_step_ms = millis();           // after the swallow/release reports flush
  Serial.println("OTP typed");
  return true;
}

static void otp_service(void) {
  if (otp_state == OTP_IDLE) return;
  uint32_t now = millis();

  if (otp_state == OTP_ARM) {
    otp_press_stroke(0);
    otp_state = OTP_HELD;
    otp_step_ms = now;
  } else if (otp_state == OTP_HELD && now - otp_step_ms >= OTP_HOLD_MS) {
    otp_release_stroke(otp_digit_idx);
    otp_state = OTP_GAP;
    otp_step_ms = now;
  } else if (otp_state == OTP_GAP && now - otp_step_ms >= OTP_GAP_MS) {
    Serial.print("OTP step ");
    Serial.print((int)(otp_digit_idx + 1));
    Serial.print('/');
    Serial.println((int)otp_ndigits);
    otp_digit_idx++;
    if (otp_digit_idx >= otp_ndigits) {
      otp_state = OTP_IDLE;
      if (otp_type_digits) {   // only a digit run consumes an OTP
        otp_counter++;
        for (uint8_t i = 0; i < HOTP_CTR_EEPROM_LEN; i++)
          EEPROM.write(HOTP_CTR_EEPROM_ADDR + i,
                       (uint8_t)(otp_counter >> (8 * i)));
      }
    } else {
      otp_press_stroke(otp_digit_idx);
      otp_state = OTP_HELD;
      otp_step_ms = now;
    }
  }
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

#if OTP_ENABLED
#define OTP_MOD_LSHIFT 0x02
#define OTP_MOD_RSHIFT 0x20
#define OTP_KEY_PRINTSCREEN 0x46

// Scan a keyboard report for the PrintScreen trigger. Plain PrintScreen
// fires the digits; Shift+PrintScreen fires the preamble. The PrintScreen
// keycode AND the Shift modifier are swallowed from the frame reaching the
// PC (so digits type clean, without Shift combos and without triggering a
// screenshot). A chord refused because OTP is busy forwards PrintScreen.
static bool otp_chord_held = false;

static void otp_scan_kb(void) {
  bool shift = (g_rep[0] & (OTP_MOD_LSHIFT | OTP_MOD_RSHIFT)) != 0;
  bool prtscr = false;
  for (uint8_t i = 2; i < 6 + 2; i++) {
    if (g_rep[i] == OTP_KEY_PRINTSCREEN) { prtscr = true; break; }
  }

  if (prtscr && shift) {
    // preamble
    if (!otp_chord_held) otp_chord_held = otp_trigger(0);
  } else if (prtscr) {
    // digits
    if (!otp_chord_held) otp_chord_held = otp_trigger(1);
  } else {
    otp_chord_held = false;
  }

  if (otp_chord_held || otp_state != OTP_IDLE) {
    g_rep[0] &= (uint8_t)~(OTP_MOD_LSHIFT | OTP_MOD_RSHIFT);   // swallow Shift
    for (uint8_t i = 2; i < 6 + 2; i++) {
      if (g_rep[i] == OTP_KEY_PRINTSCREEN) g_rep[i] = 0;       // swallow PrintScreen
    }
  }
}
#endif

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
#if OTP_ENABLED
        otp_scan_kb();               // swallow '.', and L-Ctrl while typing
#endif
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
  otp_counter = 0;
  for (uint8_t i = 0; i < HOTP_CTR_EEPROM_LEN; i++)
    otp_counter |= ((uint32_t)EEPROM.read(HOTP_CTR_EEPROM_ADDR + i)) << (8 * i);
  Serial.print("HOTP counter: ");
  Serial.println((unsigned long)otp_counter);
#if OTP_SELFTEST
  otp_selftest();
#endif
#endif

  Serial1.begin(BAUD);   // UART pins 0/1 <- Pico GPIO0
}

void loop() {
#if OTP_ENABLED
  // Provisioning/time-sync commands on ttyACM0 (CDC). Non-blocking.
  otp_service_cdc();
  // Advance the non-blocking HOTP typing state machine.
  otp_service();
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
