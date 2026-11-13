---
paths:
  - common/wivrn_serialization.h
  - common/wivrn_packets.h
---
# Wire serialization

- `bool` and enum fields are read as their underlying integer and range-checked; a bad value
  throws `deserialization_error`. Never mark them trivially serializable again: the struct and
  container fast paths `memcpy` raw network bytes into trivial fields, which is UB for them.
- An enum sent on the wire must be fully reflectable by magic_enum (default range -128..127,
  else a `magic_enum::customize::enum_range`). A value outside that range is rejected on receipt.
- Bit flags go on the wire as their underlying integer (e.g. `uint8_t flags`), not as the enum
  type: an OR of several flags is not an enumerator and would be rejected.
