/*
 * USB HID host -> raw serial forwarding, dual-channel with keyboard toggle
 *
 * Pico (arduino-pico, Earle Philhower core) as a USB host for HID devices
 * (keyboard with media keys, mouse, combo receiver, ...) through a micro-USB
 * OTG cable. Forwards EVERY raw HID report, untranslated, over serial.
 *
 * Output protocol (binary, raw HID report verbatim):
 *   0x81 <inst> <len> <b0>...<b{len-1}>   STX  dispatch  len  payload
 * No ASCII text is sent on the wire; MNT/RMV/DESC debug lines go only to
 * Serial1 (channel A) on attach/detach and are harmless to the binary parser.
 *
 * Dual output, routed to one of two receivers (Pro Micros A/B, typically on
 * two different PCs):
 *   Serial1 = UART0, TX GPIO0  -> receiver A
 *   Serial2 = UART1, TX GPIO4  -> receiver B
 * Only the selected channel gets reports. Selection is toggled by pressing
 * RIGHT-Ctrl alone on the keyboard (toggles on release). Right-Ctrl
 * combined with any other key (e.g. R-Ctrl+C) is not a switch: it is a
 * normal chord and is forwarded unchanged.
 *
 * The Holtek combo receiver (04d9:0532) ONLY streams its mouse/consumer/
 * system reports (IDs 0x03/0x02/0x01 on the multi-collection interface) in
 * REPORT protocol; TinyUSB's default BOOT protocol silences it, so we force
 * report protocol (tuh_hid_set_default_protocol). Mass Storage host is
 * disabled in the library config (CFG_TUH_MSC=0): its endless SCSI probe
 * floods the bus and starves the HID interrupt endpoints.
 *
 * Interrupt-IN receives are armed by a periodic loop pass after the device
 * is fully configured, never from the mount callback (issuing transfers
 * during enumeration wedges the remaining interfaces).
 *
 * Board settings: Raspberry Pi Pico, USB Stack = Adafruit TinyUSB Host
 * (native). Native host means no USB CDC; output is on the UARTs:
 *   GPIO0 -> Pro Micro A RX (pin 0);  GPIO4 -> Pro Micro B RX (pin 0)
 *   GPIO1/GPIO5 (UART RX) leave unconnected (receiver RX is 5V)
 *   GND shared with both Pro Micros.
 */

#include <string.h>
#include "Adafruit_TinyUSB.h"

#ifndef USE_TINYUSB_HOST
#error "Set Tools -> USB Stack -> Adafruit TinyUSB Host (native) for the Raspberry Pi Pico"
#endif

// The whole USB host stack for the native port
Adafruit_USBH_Host USBHost;

// Selected output channel (Serial1 = UART0/GPIO0 -> A, Serial2 = UART1/GPIO4 -> B)
static Stream *out = &Serial1;

// bitmask of mounted HID instances per device, for the receive-arm loop
static uint8_t mounted_mask[CFG_TUH_DEVICE_MAX + 1];

static void print_byte(Stream &s, uint8_t v) {
  if (v < 0x10) s.print('0');
  s.print(v, HEX);
}

static const char *iface_type(uint16_t usage_page, uint8_t usage) {
  if (usage_page == HID_USAGE_PAGE_DESKTOP && usage == HID_USAGE_DESKTOP_KEYBOARD) return "KBD";
  if (usage_page == HID_USAGE_PAGE_DESKTOP && usage == HID_USAGE_DESKTOP_MOUSE)    return "MSE";
  if (usage_page == HID_USAGE_PAGE_CONSUMER && usage == HID_USAGE_CONSUMER_CONTROL) return "CONS";
  return "HID";
}

void setup() {
  Serial1.begin(115200);   // UART0, TX = GPIO0 -> receiver A
  Serial2.begin(115200);   // UART1, TX = GPIO4 -> receiver B

  // The Holtek receiver only streams its mouse/consumer reports in REPORT
  // protocol; TinyUSB defaults to BOOT, which silences it.
  tuh_hid_set_default_protocol(HID_PROTOCOL_REPORT);

  USBHost.begin(0);
}

static uint32_t last_arm = 0;

void loop() {
  USBHost.task();

  // Keep one interrupt-IN read armed on every mounted interface. Never run
  // this until the device is fully configured, and never arm from the mount
  // callback: a transfer issued while the interface stack is still being
  // enumerated wedges the configuration of the remaining interfaces.
  uint32_t now = millis();
  if (now - last_arm > 25) {
    last_arm = now;
    for (uint8_t daddr = 1; daddr <= CFG_TUH_DEVICE_MAX; daddr++) {
      if (mounted_mask[daddr] && tuh_ready(daddr)) {
        for (int i = 0; i < 8; i++) {
          if ((mounted_mask[daddr] & (1 << i)) && tuh_hid_receive_ready(daddr, i)) {
            if (!tuh_hid_receive_report(daddr, i)) {
              Serial1.println("ERR queue");
            }
          }
        }
      }
    }
  }

}

// ---------------------------------------------------------------------
// TinyUSB host callbacks
// ---------------------------------------------------------------------

void tuh_hid_mount_cb(uint8_t dev_addr, uint8_t instance,
                      const uint8_t *desc_report, uint16_t desc_len) {
  static const uint8_t MAX_INFO = 4;
  tuh_hid_report_info_t info[MAX_INFO];
  uint8_t n = tuh_hid_parse_report_descriptor(info, MAX_INFO, desc_report, desc_len);

  uint16_t page  = 0;
  uint8_t  usage = 0;
  if (n) {
    page  = info[0].usage_page;
    usage = info[0].usage;
  }

  Serial1.print("MNT ");
  Serial1.print(dev_addr);
  Serial1.print(' ');
  Serial1.print(instance);
  Serial1.print(' ');
  Serial1.print(iface_type(page, usage));
  Serial1.print(" proto=");
  Serial1.println(tuh_hid_interface_protocol(dev_addr, instance));

  if (instance < 8) mounted_mask[dev_addr] |= (1 << instance);

  Serial1.print("DESC ");
  Serial1.print(dev_addr);
  Serial1.print(' ');
  Serial1.print(instance);
  Serial1.print(' ');
  Serial1.print(desc_len);
  for (uint16_t i = 0; i < desc_len; i++) {
    Serial1.print(' ');
    print_byte(Serial1, desc_report[i]);
  }
  Serial1.println();

  // NOTE: no transfers here! The interrupt-IN read is armed by loop().
}

void tuh_hid_umount_cb(uint8_t dev_addr, uint8_t instance) {
  if (instance < 8) mounted_mask[dev_addr] &= ~(1 << instance);
  Serial1.print("RMV ");
  Serial1.print(dev_addr);
  Serial1.print(' ');
  Serial1.println(instance);
}

// Right-Ctrl modifier bit in the boot-keyboard modifier byte
static const uint8_t MOD_RCTRL = 0x10;

static bool prev_rctrl = false;    // was R-Ctrl down in the previous frame?
static bool chord_seen = false;    // R-Ctrl shared a frame with another key

// Route one received report to the selected channel.
static void forward(uint8_t dev_addr, uint8_t instance,
                    const uint8_t *report, uint16_t len) {
  Stream &s = *out;
  s.write(0x81);                    // STX
  s.write(instance);                // dispatch key
  s.write((uint8_t)len);            // length
  for (uint16_t i = 0; i < len; i++) s.write(report[i]);
  s.flush();
}

void tuh_hid_report_received_cb(uint8_t dev_addr, uint8_t instance,
                                const uint8_t *report, uint16_t len) {
  // ---- Keyboard channel: solo Right-Ctrl release toggles the channel ----
  // A Right-Ctrl press is only a switch if no other key was down while it
  // was held. Right-Ctrl combined with another key (e.g. R-Ctrl+C) is a
  // normal chord: not captured, forwarded as-is.
  if (instance == 0 && len == 8) {
    bool rctrl   = (report[0] & MOD_RCTRL) != 0;
    bool any_key = false;
    for (uint8_t i = 2; i < 8; i++) {
      if (report[i] != 0) { any_key = true; break; }
    }

    if (rctrl) {
      // Right-Ctrl held: remember if it was ever combined with another key.
      if (any_key) chord_seen = true;
    } else {
      // Right-Ctrl up: toggle only for a solo press (release edge).
      if (prev_rctrl && !chord_seen) {
        out = (out == &Serial1) ? &Serial2 : &Serial1;
      }
      chord_seen = false;   // fresh R-Ctrl press may start clean
    }
    prev_rctrl = rctrl;
  }

  forward(dev_addr, instance, report, len);

  if (tuh_hid_receive_ready(dev_addr, instance)) {
    tuh_hid_receive_report(dev_addr, instance);
  }
}
