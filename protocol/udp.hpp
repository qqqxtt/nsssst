#pragma once

#include "address.hpp"
#include "ipv4.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

namespace protocol {

inline constexpr std::uint32_t UDP_HEADER_LENGTH = 8;
inline constexpr std::uint8_t IP_PROTOCOL_UDP = 17;
inline constexpr std::uint16_t UDP_MTU = 1500;

class UdpView {
  public:
    // Validates UDP Length and, if present, the IPv4 UDP checksum (pseudo-header included).
    // Header is owned; payload borrows the original mbuf chain. UDP checksum=0 is allowed.
    [[nodiscard]] static std::optional<UdpView> parse(IPv4View const &ip);

    std::uint16_t source_port() const noexcept { return read_u16(0); }
    std::uint16_t destination_port() const noexcept { return read_u16(2); }
    std::uint16_t length() const noexcept { return read_u16(4); }
    std::uint16_t checksum() const noexcept { return read_u16(6); }
    PacketSlice payload() const noexcept { return payload_; }

  private:
    explicit UdpView(std::array<unsigned char, UDP_HEADER_LENGTH> header,
                     PacketSlice payload) noexcept
        : header_(header), payload_(payload) {}
    std::uint16_t read_u16(std::size_t offset) const noexcept {
        return static_cast<std::uint16_t>((std::uint32_t{header_[offset]} << 8) |
                                          header_[offset + 1]);
    }
    std::array<unsigned char, UDP_HEADER_LENGTH> header_;
    PacketSlice payload_;
};

struct UdpEndpoint {
    Ipv4Address address;
    std::uint16_t port;
};
struct UdpDatagramView {
    UdpEndpoint source;
    UdpEndpoint destination;
    PacketSlice payload; // callback-scoped, borrows RxBatch
};
struct UdpReplyInfo {
    UdpEndpoint source;
    UdpEndpoint destination;
    MacAddress local_mac;
    MacAddress peer_mac;
};

// Synchronous construction, no payload references escape; new length/checksums computed.
[[nodiscard]] std::optional<std::vector<unsigned char>> build_udp_reply(UdpReplyInfo const &info,
                                                                        Bytes<> payload);
[[nodiscard]] std::optional<std::vector<unsigned char>> build_udp_reply(UdpReplyInfo const &info,
                                                                        PacketSlice const &payload);

} // namespace protocol
