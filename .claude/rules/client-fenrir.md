---
paths:
  - client/fenrir.*
  - client/tests/fenrir_ut.cpp
  - client/scenes/lobby_gui_fenrir.cpp
  - client/wivrn_client.*
---
# fenrir front door client (XERK-2809)

- Protocol is fenrir's `docs/vr-native-session.md` (XERK-2808); `pairing_code` must stay equal to
  fenrir's `vrPairingCode`. Tests: `test_pairing_code` in `client/tests/fenrir_ut.cpp` holds
  fenrir's all-zero vector (`fixedVRCode`).
- The front door's certificate is self-signed: curl runs with CA and host checks off, and trust is
  `CURLOPT_PINNEDPUBLICKEY` alone. Never send a request without a pin except `/pair` on a server
  not yet paired (it reads the key with `CURLOPT_CERTINFO`).
  - `/pair/confirm` must be pinned to the key `/pair` saw: the code binds that key, so a relay on
    either request makes the codes differ.
  - Session reuse is off: a resumed TLS session carries no certificate to pin or read.
- The pin is saved only once pairing succeeds, so a relayed first attempt leaves nothing behind.
- The TLS key never leaves the headset: only the certificate goes out, in the handshake.
- `fenrir.json` is separate from `client.json` so one damaged file never loses the other.
  - Damaged: moved to `.bad-<seconds>`. Unreadable (I/O): the lobby never saves over it.
  - Entries it can't parse are written back unchanged.
- A stream launched from fenrir passes the API's `serverKey` as `pinned_identity`: it is checked
  before any other handshake step, an unencrypted server or a PIN request is refused, and
  `trusted_servers` is neither read nor written.
- Background calls copy the server entry and never touch the lobby: `utils::future` threads can
  outlive it. Cancel goes through the curl progress callback.
- The wire protocol is unchanged, so the protocol hash is too.
