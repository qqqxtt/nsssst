#pragma once

#include "mbuf_slice.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>

namespace protocol {

inline constexpr std::uint32_t ETHERNET_HEADER_LENGTH = 14;

class EthernetView {
  public:
    // Snapshots the header; payload borrows the chain owned by RxBatch.
    [[nodiscard]]
    static std::optional<EthernetView> parse(rte_mbuf const &packet) noexcept {
        if (packet.pkt_len < ETHERNET_HEADER_LENGTH) {
            return std::nullopt;
        }

        std::array<unsigned char, ETHERNET_HEADER_LENGTH> scratch{};
        auto const *header = static_cast<unsigned char const *>(
            rte_pktmbuf_read(&packet, 0, ETHERNET_HEADER_LENGTH, scratch.data()));
        if (header == nullptr) {
            return std::nullopt;
        }

        std::array<unsigned char, ETHERNET_HEADER_LENGTH> snapshot{};
        std::copy_n(header, snapshot.size(), snapshot.begin());
        return EthernetView{
            snapshot, {&packet, ETHERNET_HEADER_LENGTH, packet.pkt_len - ETHERNET_HEADER_LENGTH}};
    }

    Bytes<6> destination() const noexcept {
        return Bytes<ETHERNET_HEADER_LENGTH>{header_}.first<6>();
    }

    Bytes<6> source() const noexcept {
        return Bytes<ETHERNET_HEADER_LENGTH>{header_}.subspan<6, 6>();
    }

    std::uint16_t ether_type() const noexcept {
        return static_cast<std::uint16_t>((std::uint32_t{header_[12]} << 8) | header_[13]);
    }

    PacketSlice payload() const noexcept {
        return payload_;
    }

  private:
    explicit EthernetView(std::array<unsigned char, ETHERNET_HEADER_LENGTH> header,
                          PacketSlice payload) noexcept
        : header_(header), payload_(payload) {}

    std::array<unsigned char, ETHERNET_HEADER_LENGTH> header_;
    PacketSlice payload_;
};

} // namespace protocol
