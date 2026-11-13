---
paths:
  - server/driver/wivrn_wheel*
  - server/driver/wivrn_uinput.*
  - common/wivrn_packets.h
---
# Wheels plugged into the headset (XERK-2850, epic XERK-2848)

- Packets: `from_headset::wheel_added/removed/state`, `to_headset::wheel_ff`, shared
  `wheel_ff_effect`. Codes and units are Linux input's (`linux/input.h`), so no table to keep.
  - They are in the protocol hash: server and Quest APK must come from the same commit.
  - `wheel_state.keys` is a bitmap indexed by position in `wheel_added.keys`: `sanitize` replaces
    a refused key with 0 instead of removing it, or every later bit would shift.
- Backend: `DIREWOLF_WHEEL_SOCKET` set → fenrir's helper; else local uinput only if
  `hid-forwarding` is on. fenrir VR pods have no /dev/uinput, so the helper is the only path there.
- Helper socket: SOCK_SEQPACKET, one JSON object per packet; keys agreed with fenrir XERK-2852
  (`create`/`events`/`destroy` → `created`/`error`/`ff`). Rename a key on both sides at once.
  - `sanitize`'s limits (4 wheels, ≤64 effects, key/abs ranges, 79-byte printable name) are the
    helper's: anything wider is refused there. Keep them equal.
  - The helper acks kernel FF uploads itself; local uinput acks at once in `poll`. Either way the
    game never waits on the headset.
  - A closed connection drops its wheels on the helper: the next send fails and `manager` recreates
    the wheel (1 s backoff), reconnecting.
- `wheel_ff` goes on the control channel: a lost upload leaves the wheel without an effect.
- Wheels are cleared on `pause_session`: the headset must send `wheel_added` again on reconnect.
- Tests: `server/driver/wivrn_wheel_ut.cpp` (Sockets-UT.yml). Its uinput part needs root and the
  uinput module; CI sets `WIVRN_REQUIRE_UINPUT=1` so a missing /dev/uinput fails instead of skipping.
