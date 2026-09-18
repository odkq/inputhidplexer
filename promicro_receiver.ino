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

#include <string.h>

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

  Serial1.begin(BAUD);   // UART pins 0/1 <- Pico GPIO0
}

void loop() {
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