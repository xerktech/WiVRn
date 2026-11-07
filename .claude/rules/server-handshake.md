---
paths:
  - server/main.cpp
  - server/accept_connection.*
  - server/handshake_pool*
  - server/driver/wivrn_connection.*
  - common/wivrn_sockets.*
---
# Server handshake

- Handshakes run in two phases: `wivrn_connection::authenticate` (concurrent, one thread per peer
  in `handshake_pool`) and `wivrn_connection::init` (one at a time, after a peer is authenticated).
  - Anything that can stall on the peer (PIN entry, first record) belongs in `authenticate`.
  - `authenticate` must only touch its own socket: no IPC socket, no UDP port bind.
  - Shared state touched there needs a lock (see `identity_key_mutex`).
- Keep the `handshake_gate` open until a handshake fully succeeds; closing it drops every peer
  queued in it, including a headset that already sent its handshake.
- Wrong PINs are throttled by `pin_throttle`, never by delaying the listener: paired headsets must
  not wait because someone guessed a PIN.

## Verifying without a full build
- The full server needs Monado and many system packages; CI Build is the only full compile.
- `handshake_pool_ut` and `wivrn_sockets_ut` build standalone: see the g++ lines in
  `.github/workflows/Sockets-UT.yml`. Also run them under `-fsanitize=thread`.
- `server/driver/wivrn_connection.cpp` syntax-checks with `g++ -fsyntax-only` given OpenXR SDK
  headers, nlohmann/json, boost/pfr and a stub `wivrn_config.h` defining `wivrn::default_port`.
