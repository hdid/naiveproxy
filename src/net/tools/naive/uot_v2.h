// Copyright 2026
// UoT v2 wire-format helpers for SOCKS5 UDP datagrams.
#ifndef NET_TOOLS_NAIVE_UOT_V2_H_
#define NET_TOOLS_NAIVE_UOT_V2_H_

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "net/base/host_port_pair.h"

namespace net {

constexpr char kUotV2MagicAddress[] = "sp.v2.udp-over-tcp.arpa";

std::string MakeUotV2Request(bool is_connect,
                             const HostPortPair& destination);

bool AppendUotV2Frame(bool is_connect,
                      const HostPortPair& destination,
                      std::string_view payload,
                      std::string* output);

bool ConsumeUotV2Frame(std::string* input,
                       bool is_connect,
                       const HostPortPair& fixed_destination,
                       size_t max_payload,
                       HostPortPair* destination,
                       std::string* payload);

bool EncodeSocks5UdpDatagram(const HostPortPair& destination,
                             std::string_view payload,
                             std::string* output);

bool DecodeSocks5UdpDatagram(std::string_view packet,
                             HostPortPair* destination,
                             std::string_view* payload);

}  // namespace net

#endif  // NET_TOOLS_NAIVE_UOT_V2_H_
