---
paths:
  - common/wivrn_serialization.h
  - common/wivrn_packets.h
  - common/test_serialization.cpp
---
# Wire serialization

- `bool` and enum fields are read as their underlying integer and range-checked; a bad value
  throws `deserialization_error`. Never mark them trivially serializable again: the struct and
  container fast paths `memcpy` raw network bytes into trivial fields, which is UB for them.
- `std::byte` is the exception: it is an enum with no enumerators and carries raw data (icons),
  so it has its own trivially serializable specialization with no check.
- An enum sent on the wire must be fully reflectable by magic_enum (default range -128..127).
  - Otherwise its out-of-range values are rejected on receipt and missing from the protocol hash.
  - Widen it with `magic_enum::customize::enum_range`, declared right after the enum and before
    any use (`device_id` goes to 255 for its gamepad ids).
  - A static_assert in the enum traits fails the build when an enumerator sits at the top of the
    reflection range, which is the usual sign of truncation.
- Bit flags go on the wire as their underlying integer (e.g. `uint8_t flags`), not as the enum
  type: an OR of several flags is not an enumerator and would be rejected.
- An uncaught `deserialization_error` in the server's packet loop pauses the session and makes the
  headset reconnect, so wrongly rejecting a legitimate value is a stream drop, not a dropped packet.
- Tests: `common/test_serialization.cpp` (CI step "Test serialization").
