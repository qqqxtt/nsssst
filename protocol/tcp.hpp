#pragma once

#include "ipv4.hpp"
#include <array>
#include <cstdint>
#include <optional>

namespace protocol {
inline constexpr std::uint8_t IP_PROTOCOL_TCP = 6;
inline constexpr std::uint32_t TCP_HEADER_LENGTH = 20;
inline constexpr std::uint32_t TCP_MAX_HEADER_LENGTH = 60;

enum class TcpFlag : std::uint8_t {
    Fin = 0x01,
    Syn = 0x02,
    Rst = 0x04,
    Psh = 0x08,
    Ack = 0x10,
    Urg = 0x20,
    Ece = 0x40,
    Cwr = 0x80
};

class TcpView {
  public:
    // Owns a header snapshot (including options); payload borrows the RX mbuf chain.
    // Validates the entire TCP checksum, including the IPv4 pseudo-header.
    [[nodiscard]] static std::optional<TcpView> parse(IPv4View const &ip);

    std::uint16_t source_port() const noexcept { return read_u16(0); }
    std::uint16_t destination_port() const noexcept { return read_u16(2); }
    std::uint32_t sequence_number() const noexcept { return read_u32(4); }
    std::uint32_t acknowledgment_number() const noexcept { return read_u32(8); }
    std::uint8_t header_length() const noexcept { return (header_[12] >> 4) * 4; }
    std::uint8_t flags() const noexcept { return header_[13]; }
    bool has_flag(TcpFlag flag) const noexcept {
        return (flags() & static_cast<std::uint8_t>(flag)) != 0;
    }
    std::uint16_t window() const noexcept { return read_u16(14); }
    std::uint16_t checksum() const noexcept { return read_u16(16); }
    std::uint16_t urgent_pointer() const noexcept { return read_u16(18); }
    // Validated option bytes, including NOP/EOL/padding; borrows this view.
    // Unknown option kinds are retained, not rejected. No option negotiation is performed.
    Bytes<> options() const noexcept {
        return Bytes<>{header_}.subspan(TCP_HEADER_LENGTH, header_length() - TCP_HEADER_LENGTH);
    }
    PacketSlice payload() const noexcept { return payload_; }

  private:
    explicit TcpView(std::array<unsigned char, TCP_MAX_HEADER_LENGTH> header,
                     PacketSlice payload) noexcept
        : header_(header), payload_(payload) {}
    std::uint16_t read_u16(std::size_t offset) const noexcept {
        return static_cast<std::uint16_t>((std::uint32_t{header_[offset]} << 8) |
                                          header_[offset + 1]);
    }
    std::uint32_t read_u32(std::size_t offset) const noexcept {
        return (std::uint32_t{read_u16(offset)} << 16) | read_u16(offset + 2);
    }
    std::array<unsigned char, TCP_MAX_HEADER_LENGTH> header_;
    PacketSlice payload_;
};
} // namespace protocol
