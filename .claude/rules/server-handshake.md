---
paths:
  - server/main.cpp
  - server/accept_connection.*
  - server/handshake_pool*
  - server/driver/wivrn_connection.*
  - server/driver/authenticate*
  - server/driver/known_keys.h
  - common/wivrn_sockets.*
---
# Server handshake

- Handshakes run in two phases: `wivrn::authenticate` (concurrent, one thread per peer
  in `handshake_pool`) and `wivrn_connection::init` (one at a time, after a peer is authenticated).
  - Anything that can stall on the peer (PIN entry, first record) belongs in `authenticate`.
  - `authenticate` must only touch its own socket: no IPC socket, no UDP port bind.
  - Shared state touched there needs a lock (see `identity_key_mutex`).
- `handshake_pool` evicts only an attempt that has waited on its peer for `stall_after`, and drops
  the newcomer otherwise. Both alternatives failed QA:
  - evicting by start order let a burst of junk connections cancel a headset mid-handshake;
  - leaving newcomers queued in the gate let a flood of ~32 stalled connections/s lock it out.
  - `authenticate` must report its waits (the `waiting` callback) for this to work.
- Of the stalled attempts it evicts the longest waiter. The other ordering is no better (XERK-2766):
  - A person typing the PIN (up to 2 min) is the longest waiter, so 16 stalled LAN peers that keep
    reconnecting can stop pairing; paired headsets (~0.15 s) are unaffected. Accepted as LAN risk.
  - Evicting the newest staller failed QA: a person who joins a pool already full of stallers is
    then the newest, so it made pairing easier to block than the current rule.
  - Exempting PIN waiters can't work either: attackers reach the PIN step too.
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
- `handshake_pool_ut`, `wivrn_sockets_ut` and `authenticate_ut` build standalone: see the g++
  lines in `.github/workflows/Sockets-UT.yml`. Also run them under `-fsanitize=thread`.
- `authenticate.cpp` is its own file so its test links without configuration, IPC or Monado.
  - It reaches the key store only through `known_keys.h`; the test defines those functions.
  - Keep it that way: including `configuration.h` or `wivrn_ipc.h` there breaks the CI test.
- `server/driver/wivrn_connection.cpp` syntax-checks with `g++ -fsyntax-only` given OpenXR SDK
  headers, nlohmann/json, boost/pfr and a stub `wivrn_config.h` defining `wivrn::default_port`.
- OpenXR headers must be 1.1.59 (Ubuntu's 1.0.20 lacks types `wivrn_packets.h` uses).
- `authenticate_ut`'s throttle test drives 8 wrong PINs, so the `pin_throttle` growth
  (`initial_delay`, doubling) and the 8s wait in `pin_attempt` bound it: change them together.
- LeakSanitizer aborts at exit in sandboxes without ptrace. `ASAN_OPTIONS=detect_leaks=0` works
  around it locally, but CI keeps LSan on: replay leaks in a chroot or with ptrace before pushing.
- Handshakes each run on a new thread, so a `thread_local` holding an allocation must free it on
  thread exit (see `bn_ctx` in `common/smp.cpp`), or every connection leaks it.
