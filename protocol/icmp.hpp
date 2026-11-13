#pragma once

#include "ipv4.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

namespace protocol {

inline constexpr std::uint32_t ICMP_ECHO_HEADER_LENGTH = 8;
inline constexpr std::uint8_t IP_PROTOCOL_ICMP = 1;
inline constexpr std::uint16_t ICMP_ECHO_MTU = 1500;

enum class IcmpEchoType : std::uint8_t { Reply = 0, Request = 8 };

class ICMPEchoView {
  public:
    [[nodiscard]] static std::optional<ICMPEchoView> parse(PacketSlice const& message);

    IcmpEchoType type() const noexcept { return static_cast<IcmpEchoType>(header_[0]); }
    std::uint8_t code() const noexcept { return header_[1]; }
    std::uint16_t identifier() const noexcept { return read_u16(4); }
    std::uint16_t sequence() const noexcept { return read_u16(6); }
    PacketSlice payload() const noexcept { return payload_; }

  private:
    explicit ICMPEchoView(
        std::array<unsigned char, ICMP_ECHO_HEADER_LENGTH> header, PacketSlice payload) noexcept
        : header_(header),
          payload_(payload) {}
    std::uint16_t read_u16(std::size_t offset) const noexcept {
        return static_cast<std::uint16_t>(
            (std::uint32_t{header_[offset]} << 8) | header_[offset + 1]);
    }
    std::array<unsigned char, ICMP_ECHO_HEADER_LENGTH> header_;
    PacketSlice payload_;
};

[[nodiscard]] std::optional<std::vector<unsigned char>> build_icmp_echo_reply(
    IPv4View const& request, Bytes<6> local_mac, Bytes<6> peer_mac);

} // namespace protocol
