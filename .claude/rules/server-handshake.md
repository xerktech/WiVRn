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
- `handshake_pool` evicts only an attempt that has waited on its peer for `stall_after`, and drops
  the newcomer otherwise. Both alternatives failed QA:
  - evicting by start order let a burst of junk connections cancel a headset mid-handshake;
  - leaving newcomers queued in the gate let a flood of ~32 stalled connections/s lock it out.
  - `authenticate` must report its waits (the `waiting` callback) for this to work.
- Keep the `handshake_gate` open until a handshake fully succeeds; closing it drops every peer
  queued in it, including a headset that already sent its handshake.
- Wrong PINs are throttled by `pin_throttle`, never by delaying the listener: paired headsets must
  not wait because someone guessed a PIN.
  - `pin_attempt` waits (under 8s, the headset's own wait for `pin_check_2`) instead of refusing;
    it reports that wait through `waiting` so the pool can still evict it.
- `authenticate` caps TCP records at 64 KiB and restores the default before handing the socket on:
  a length prefix alone makes `TCP::receive_raw` allocate the whole record.

## Verifying without a full build
- The full server needs Monado and many system packages; CI Build is the only full compile.
- `handshake_pool_ut` and `wivrn_sockets_ut` build standalone: see the g++ lines in
  `.github/workflows/Sockets-UT.yml`. Also run them under `-fsanitize=thread`.
- `server/driver/wivrn_connection.cpp` syntax-checks with `g++ -fsyntax-only` given OpenXR SDK
  headers, nlohmann/json, boost/pfr and a stub `wivrn_config.h` defining `wivrn::default_port`.
