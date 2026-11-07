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
- Accepted risk: a LAN flood (~60k connections/s from 32+ addresses, reconnecting at once) keeps
  every slot younger than `stall_after`, so paired headsets are dropped until the flood stops.
  - Before its first record, a headset looks the same as any other connection, so no admission
    rule can rank it above the flood.
  - Rejected fixes: per-address rate limits (32 addresses still take freed slots ~80x faster
    than a headset retries); evicting young attempts (brings back the junk-burst bug above);
    priority for a claimed known key (the key is sent in clear, so it can be replayed, and a slot
    lasts less than a Wi-Fi round trip).
- Keep the `handshake_gate` open until a handshake fully succeeds; closing it drops every peer
  queued in it, including a headset that already sent its handshake.
- Wrong PINs are throttled by `pin_throttle`, never by delaying the listener: paired headsets must
  not wait because someone guessed a PIN.
- Take the `pin_attempt` only after the last `receive` of the PIN exchange (pin_check_3).
  - Holding it across a peer wait let one stalled connection per 10 s block all pairing.
  - SMP leaks nothing about the PIN before pin_check_4, so earlier steps need no throttle.
  - `pin_attempt` waits (under 8s, the headset's own wait for `pin_check_4`) instead of refusing;
    it reports that wait through `waiting` so the pool can still evict it.
- `authenticate` caps TCP records at 64 KiB and restores the default before handing the socket on:
  a length prefix alone makes `TCP::receive_raw` allocate the whole record.

## Verifying without a full build
- The full server needs Monado and many system packages; CI Build is the only full compile.
- `handshake_pool_ut` and `wivrn_sockets_ut` build standalone: see the g++ lines in
  `.github/workflows/Sockets-UT.yml`. Also run them under `-fsanitize=thread`.
- `server/driver/wivrn_connection.cpp` syntax-checks with `g++ -fsyntax-only` given OpenXR SDK
  headers, nlohmann/json, boost/pfr and a stub `wivrn_config.h` defining `wivrn::default_port`.
