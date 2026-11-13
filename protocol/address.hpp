#pragma once
#include <algorithm>
#include <array>
namespace protocol {
using MacAddress = std::array<unsigned char, 6>;
using Ipv4Address = std::array<unsigned char, 4>;
struct LocalAddress {
    MacAddress mac;
    Ipv4Address ip;
};
inline bool valid_peer_ip(Ipv4Address ip) noexcept {
    return ip[0] != 0 and ip[0] != 127 and ip[0] < 224;
}
inline bool valid_peer_mac(MacAddress mac) noexcept {
    return (mac[0] & 1) == 0 and std::any_of(mac.begin(), mac.end(), [](auto b) { return b != 0; });
}
} // namespace protocol
