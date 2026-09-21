# inputhidplexer. Keyboard (and mouse) instantaneous multiplexer

Previously I used a usb switch to share a keyboard and mouse (Tex Shura)
between two computers. This had some drawbacks:

- Slow, as the keyboard is reinitialized each time you switch
- Can't use a keychord to change from one computer to another and even a
  'satellite' button is cumbersome to use

This project links a Raspberry Pi Pico to connect the keyboard with a
OTG usb cable and two Sparkfun Pro Micro controllers that can act as USB
gadgets

When pressing 'Right Control' the input switches _instantaneously_ from
one computer to the other.

## OTP (one-time password)

One of the two Pro Micros can also act as a HOTP RNG typed into the
computer it is plugged into. Set `OTP_ENABLED 1` in
`promicro_receiver/promicro_receiver.ino` on that receiver (keep the other
at `0` so it stays a plain pass-through).

- **Secret**: RFC 4648 base32, **baked into firmware Flash** at compile
  time (`OTP_SECRET_B32`). There is no runtime provisioning and no read-back
  path from ttyACM0, so a software attacker on the PC cannot extract it
  (only a reflash/ICSP-style attacker could - set the AVR lock bits
  LB1+LB2 after flashing to block even that; a chip-erase then destroys the
  secret). **Set `OTP_SECRET_B32` before flashing.**
- **Trigger**: press **PrintScr** on the keyboard while the OTP
  channel is the active one. The key is swallowed 
  and the 6-digit code is typed. If the key is refused (no/stale
  sync), the PrntScr is forwarded normally.
- **Self-test**: on boot the receiver checks the TOTP implementation
  against RFC 6238 vectors (`OTP_SELFTEST`), printing PASS/FAIL to ttyACM0.

## Preamble (or permanent password)

The defined OTP_PREAMBLE (if any) will be typed when entering Shift+PrintSrc

Setup:

```
# edit OTP_SECRET_B32 in promicro_receiver/promicro_receiver.ino, then flash.
```

## Usage of LLMs

This has been programmed using the "Open Pickle" model (free) from Open
Code. Debugging and several reflashing and trial/error was needed but
the model showed expertise in the Arduino libraries and in the subtleties
of USB communication

## Switching keys sent to the host. Control+comma

Control+Comma is sent to the currently connected computer just before
the switch. I use it in the sway configuration to call ddcutil and
change the current input for my VESA-compatible monitor (One of the
machines switches to the input of the other one). Like:

```
bindsym Control+comma exec ddccontrol -r 0x60 -w 15 dev:/dev/i2c-0
```

<img width="917" height="517" alt="image" src="https://github.com/user-attachments/assets/751d0d05-da04-414d-832c-db4533ee16ae" />

