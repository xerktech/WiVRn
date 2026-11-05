#include "wivrn_packets.h"
#include "wivrn_serialization.h"

#pragma once

namespace wivrn
{
using protocol = std::variant<from_headset::packets, to_headset::packets>;
// The TCP and UDP sockets use AES-128-GCM (authenticated) records instead of AES-CTR.
// Mixed into the version so a peer using the old wire format is refused at the handshake
// instead of failing every packet's authentication.
static constexpr int aead_revision = 0x10000;
static inline const constinit auto protocol_version = serialization_type_hash<protocol>(protocol_revision + aead_revision);
} // namespace wivrn
