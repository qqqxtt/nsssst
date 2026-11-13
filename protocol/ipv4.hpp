#pragma once

#include "mbuf_slice.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>

namespace protocol {

inline constexpr std::uint32_t IPV4_HEADER_LENGTH = 20;

class IPv4View {
  public:
    [[nodiscard]] static std::optional<IPv4View> parse(PacketSlice const& packet) noexcept {
        if (packet.packet == nullptr or packet.offset > packet.packet->pkt_len or
            packet.length > packet.packet->pkt_len - packet.offset or
            packet.length < IPV4_HEADER_LENGTH) {
            return std::nullopt;
        }

        std::array<unsigned char, IPV4_HEADER_LENGTH> scratch{};
        auto const* header = static_cast<unsigned char const*>(
            rte_pktmbuf_read(packet.packet, packet.offset, IPV4_HEADER_LENGTH, scratch.data()));
        if (header == nullptr or header[0] != 0x45) {
            return std::nullopt; // Version 4, IHL=5; options are not supported yet.
        }

        std::array<unsigned char, IPV4_HEADER_LENGTH> snapshot{};
        std::copy_n(header, snapshot.size(), snapshot.begin());
        IPv4View result{snapshot, packet};
        if (result.total_length() < IPV4_HEADER_LENGTH or result.total_length() > packet.length or
            (result.read_u16(6) & 0xbfff) != 0 or not result.valid_checksum()) {
            // Only DF may be set: reserved bit, MF and fragment offset must be zero.
            return std::nullopt;
        }

        result.payload_.offset += IPV4_HEADER_LENGTH;
        result.payload_.length = result.total_length() - IPV4_HEADER_LENGTH;
        return result;
    }

    std::uint8_t version() const noexcept { return header_[0] >> 4; }
    std::uint8_t header_length() const noexcept { return (header_[0] & 0x0f) * 4; }
    std::uint8_t dscp() const noexcept { return header_[1] >> 2; }
    std::uint8_t ecn() const noexcept { return header_[1] & 3; }
    std::uint16_t total_length() const noexcept { return read_u16(2); }
    std::uint16_t identification() const noexcept { return read_u16(4); }
    bool dont_fragment() const noexcept { return (read_u16(6) & 0x4000) != 0; }
    std::uint8_t ttl() const noexcept { return header_[8]; }
    std::uint8_t protocol() const noexcept { return header_[9]; }
    std::uint16_t header_checksum() const noexcept { return read_u16(10); }

    Bytes<4> source() const noexcept { return Bytes<IPV4_HEADER_LENGTH>{header_}.subspan<12, 4>(); }
    Bytes<4> destination() const noexcept {
        return Bytes<IPV4_HEADER_LENGTH>{header_}.subspan<16, 4>();
    }
    PacketSlice payload() const noexcept { return payload_; }

  private:
    explicit IPv4View(
        std::array<unsigned char, IPV4_HEADER_LENGTH> header, PacketSlice payload) noexcept
        : header_(header),
          payload_(payload) {}

    std::uint16_t read_u16(std::size_t offset) const noexcept {
        return static_cast<std::uint16_t>(
            (std::uint32_t{header_[offset]} << 8) | header_[offset + 1]);
    }
    bool valid_checksum() const noexcept {
        std::uint32_t sum{};
        for (std::size_t i = 0; i < header_.size(); i += 2) {
            sum += read_u16(i);
        }
        while ((sum >> 16) != 0) {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        return sum == 0xffff;
    }

    std::array<unsigned char, IPV4_HEADER_LENGTH> header_;
    PacketSlice payload_;
};

} // namespace protocol
