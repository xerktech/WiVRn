---
paths:
  - client/wheel/**
  - client/android/usb_wheel.*
  - client/java/Wheel.java
  - client/tests/wheel_ut.cpp
---
# G920 wheel on the headset's USB port (XERK-2851)

- Epic XERK-2848 holds the wire contract; the server side is XERK-2850 (`server/driver`).
  - Send `wheel_added` on every stream start: the server forgets wheels on disconnect.
  - The first `wheel_state` after `wheel_added` carries every axis; later ones only changes.
  - Server limits: 4 wheels, 64 effects, keys BTN_MISC..BTN_GEAR_UP or BTN_TRIGGER_HAPPY*.
- The HID++ force feedback code is written from the protocol, not copied from the kernel's
  `hid-logitech-hidpp.c`: that file is GPL-2-only, WiVRn is GPL-3. Keep it that way.
- Effects with more than 16 parameters (periodic, conditions, autocenter) go in a very long
  report (0x12, 64 bytes); a long report (0x11) would cut them.
- Input fields come from the device's report descriptor, mapped as Linux hid-input maps them,
  never from hard-coded offsets: the server's virtual wheel must look like the real device.
- Lifetimes:
  - `usb_wheel::sink` is never called after its destructor returns; `stop_stream` runs at
    the start of `~stream`, before the session it sends to is destroyed.
  - Java never closes a connection on detach by itself: native code destroys the wheel
    (joins its threads) and then calls `Wheel.close`, so no ioctl runs on a closed fd.
  - JNI callbacks only queue events; `manager::poll` (application thread, has a JNI env)
    handles them. Native threads can't `FindClass` app classes: reach `Wheel` through
    `MainActivity.wheel`.
- FF requests are folded into per-effect pending state (latest definition, latest play/stop,
  erase), latest gain and autocenter; never a FIFO with a cap. Two capped queues failed QA:
  a flood either grew memory without bound or dropped the stop of a playing effect.
  - Bounded by `known_effects` (64) plus `device_effects`; an erase of an effect that never
    reached the wheel just drops its pending entry.
- Permission is checked with `UsbManager.hasPermission`, never from the intent extra.
- Not yet checked on hardware: the mode switch message and its endpoint (usb_modeswitch's
  046d:c261 entry), and the HID++ parameter layouts. `log_wheel_ff` logs each FF request.
- Tests: `client/tests/wheel_ut.cpp` (CI: Sockets-UT `wheel_ut`).
