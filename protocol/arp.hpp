#pragma once

#include "mbuf_slice.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>

namespace protocol {

// Supported format: Ethernet (6-byte MAC) and IPv4 (4-byte address).
inline constexpr std::uint32_t ARP_HEADER_LENGTH = 28;

enum class ArpOperation : std::uint16_t { Request = 1, Reply = 2 };

class ARPView {
  public:
    [[nodiscard]] static std::optional<ARPView> parse(PacketSlice const& payload) noexcept {
        if (payload.packet == nullptr or payload.offset > payload.packet->pkt_len or
            payload.length > payload.packet->pkt_len - payload.offset or
            payload.length < ARP_HEADER_LENGTH) {
            return std::nullopt;
        }

        std::array<unsigned char, ARP_HEADER_LENGTH> scratch{};
        auto const* header = static_cast<unsigned char const*>(
            rte_pktmbuf_read(payload.packet, payload.offset, ARP_HEADER_LENGTH, scratch.data()));
        if (header == nullptr) {
            return std::nullopt;
        }

        std::array<unsigned char, ARP_HEADER_LENGTH> snapshot{};
        std::copy_n(header, snapshot.size(), snapshot.begin());
        ARPView result{snapshot};
        if (result.hardware_type() != 1 or result.protocol_type() != 0x0800 or
            result.hardware_length() != 6 or result.protocol_length() != 4 or
            (result.operation() != ArpOperation::Request and
                result.operation() != ArpOperation::Reply)) {
            return std::nullopt;
        }
        return result;
    }

    std::uint16_t hardware_type() const noexcept { return read_u16(0); }
    std::uint16_t protocol_type() const noexcept { return read_u16(2); }
    std::uint8_t hardware_length() const noexcept { return header_[4]; }
    std::uint8_t protocol_length() const noexcept { return header_[5]; }
    ArpOperation operation() const noexcept { return static_cast<ArpOperation>(read_u16(6)); }

    Bytes<6> sender_hardware_address() const noexcept {
        return Bytes<ARP_HEADER_LENGTH>{header_}.subspan<8, 6>();
    }
    Bytes<4> sender_protocol_address() const noexcept {
        return Bytes<ARP_HEADER_LENGTH>{header_}.subspan<14, 4>();
    }
    Bytes<6> target_hardware_address() const noexcept {
        return Bytes<ARP_HEADER_LENGTH>{header_}.subspan<18, 6>();
    }
    Bytes<4> target_protocol_address() const noexcept {
        return Bytes<ARP_HEADER_LENGTH>{header_}.subspan<24, 4>();
    }

  private:
    explicit ARPView(std::array<unsigned char, ARP_HEADER_LENGTH> header) noexcept
        : header_(header) {}

    std::uint16_t read_u16(std::size_t offset) const noexcept {
        return static_cast<std::uint16_t>(
            (std::uint32_t{header_[offset]} << 8) | header_[offset + 1]);
    }

    std::array<unsigned char, ARP_HEADER_LENGTH> header_;
};

} // namespace protocol
