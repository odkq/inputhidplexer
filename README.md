# keyplexer. Keyboard (and mouse) instantaneous multiplexer

Before, I used a usb switch to share a keyboard and mouse (Tex Shura)
between two computers. This had some drawbacks:

- Slow, as the keyboard is reinitialized each time you switch
- Can't use a keychord to change from one computer to another and even a
  'satellite' button is cumbersome to use

This project links a Raspberry Pi Pico to connect the keyboard with a
OTG usb cable and two Sparkfun Pro Micro controllers that can act as USB
gadgets

When pressing 'Right Control' the input switches _instantaneously_ from
one computer to the other.

## Usage of LLMs

This has been programmed using the "Open Pickle" model (free) from Open
Code. Debugging and several reflashing and trial/error was needed but
the model showed expertise in the Arduino libraries and in the subtleties
of USB communication

## Posible addons

Smart keycard: An OTP generator that sends a preconfigured OTP on a
certain keychord

<img width="917" height="517" alt="image" src="https://github.com/user-attachments/assets/751d0d05-da04-414d-832c-db4533ee16ae" />

