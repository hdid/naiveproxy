// Copyright 2026
#include "net/tools/naive/uot_v2.h"

#include <limits>

#include "base/containers/span.h"
#include "net/base/ip_address.h"

namespace net {
namespace {

bool AppendAddress(std::string_view host,
                   uint16_t port,
                   bool packet_address,
                   std::string* output) {
  IPAddress ip;
  if (ip.AssignFromIPLiteral(host)) {
    if (ip.IsIPv4()) {
      output->push_back(packet_address ? '\\x00' : '\\x01');
    } else if (ip.IsIPv6()) {
      output->push_back(packet_address ? '\\x01' : '\\x04');
    } else {
      return false;
    }
    for (uint8_t byte : ip.bytes()) {
      output->push_back(static_cast<char>(byte));
    }
  } else {
    if (host.empty() || host.size() > 255) {
      return false;
    }
    output->push_back(packet_address ? '\\x02' : '\\x03');
    output->push_back(static_cast<char>(host.size()));
    output->append(host);
  }
  output->push_back(static_cast<char>(port >> 8));
  output->push_back(static_cast<char>(port & 0xff));
  return true;
}

bool ConsumeAddress(std::string_view* input,
                    bool packet_address,
                    HostPortPair* destination) {
  if (input->empty()) {
    return false;
  }
  uint8_t atyp = static_cast<uint8_t>((*input)[0]);
  input->remove_prefix(1);
  size_t address_size = 0;
  bool domain = false;
  if ((!packet_address && atyp == 0x01) ||
      (packet_address && atyp == 0x00)) {
    address_size = 4;
  } else if ((!packet_address && atyp == 0x04) ||
             (packet_address && atyp == 0x01)) {
    address_size = 16;
  } else if ((!packet_address && atyp == 0x03) ||
             (packet_address && atyp == 0x02)) {
    if (input->empty()) {
      return false;
    }
    address_size = static_cast<uint8_t>((*input)[0]);
    input->remove_prefix(1);
    domain = true;
    if (address_size == 0) {
      return false;
    }
  } else {
    return false;
  }
  if (input->size() < address_size + 2) {
    return false;
  }

  std::string host;
  if (domain) {
    host.assign(input->substr(0, address_size));
  } else {
    IPAddress ip(base::span(
        reinterpret_cast<const uint8_t*>(input->data()), address_size));
    host = ip.ToString();
  }
  input->remove_prefix(address_size);
  uint16_t port = (static_cast<uint8_t>((*input)[0]) << 8) |
                  static_cast<uint8_t>((*input)[1]);
  input->remove_prefix(2);
  *destination = HostPortPair(host, port);
  return true;
}

}  // namespace

std::string MakeUotV2Request(bool is_connect,
                             const HostPortPair& destination) {
  std::string output;
  output.push_back(is_connect ? '\\x01' : '\\x00');
  if (!AppendAddress(destination.host(), destination.port(), false, &output)) {
    return {};
  }
  return output;
}

bool AppendUotV2Frame(bool is_connect,
                      const HostPortPair& destination,
                      std::string_view payload,
                      std::string* output) {
  if (payload.empty() || payload.size() > std::numeric_limits<uint16_t>::max()) {
    return false;
  }
  if (!is_connect &&
      !AppendAddress(destination.host(), destination.port(), true, output)) {
    return false;
  }
  uint16_t size = static_cast<uint16_t>(payload.size());
  output->push_back(static_cast<char>(size >> 8));
  output->push_back(static_cast<char>(size & 0xff));
  output->append(payload);
  return true;
}

bool ConsumeUotV2Frame(std::string* input,
                       bool is_connect,
                       const HostPortPair& fixed_destination,
                       size_t max_payload,
                       HostPortPair* destination,
                       std::string* payload) {
  std::string_view view(*input);
  HostPortPair parsed_destination = fixed_destination;
  if (!is_connect && !ConsumeAddress(&view, true, &parsed_destination)) {
    return false;
  }
  if (view.size() < 2) {
    return false;
  }
  size_t size = (static_cast<uint8_t>(view[0]) << 8) |
                static_cast<uint8_t>(view[1]);
  if (size == 0 || size > max_payload) {
    return false;
  }
  if (view.size() < size + 2) {
    return false;
  }
  view.remove_prefix(2);
  payload->assign(view.substr(0, size));
  size_t consumed = input->size() - (view.size() - size);
  input->erase(0, consumed);
  *destination = parsed_destination;
  return true;
}

bool EncodeSocks5UdpDatagram(const HostPortPair& destination,
                             std::string_view payload,
                             std::string* output) {
  output->assign("\\x00\\x00\\x00", 3);
  if (!AppendAddress(destination.host(), destination.port(), false, output)) {
    return false;
  }
  output->append(payload);
  return true;
}

bool DecodeSocks5UdpDatagram(std::string_view packet,
                             HostPortPair* destination,
                             std::string_view* payload) {
  if (packet.size() < 4 || packet[0] != '\\x00' ||
      packet[1] != '\\x00' || packet[2] != '\\x00') {
    return false;
  }
  packet.remove_prefix(3);
  if (!ConsumeAddress(&packet, false, destination)) {
    return false;
  }
  *payload = packet;
  return true;
}

}  // namespace net
