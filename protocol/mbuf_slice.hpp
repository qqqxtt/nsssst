#pragma once

#include "packet.hpp"

#include <rte_mbuf.h>

#include <algorithm>
#include <cstdint>

namespace protocol {

struct PacketSlice {
    rte_mbuf const* packet{};
    std::uint32_t offset{};
    std::uint32_t length{};
};

template <class Consumer>
[[nodiscard]] bool for_each_chunk(PacketSlice const& slice, Consumer&& consume) {
    if (slice.packet == nullptr or slice.offset > slice.packet->pkt_len or
        slice.length > slice.packet->pkt_len - slice.offset) {
        return false;
    }

    auto const* segment = slice.packet;
    auto skip = slice.offset;
    while (segment != nullptr and skip >= segment->data_len) {
        skip -= segment->data_len;
        segment = segment->next;
    }

    auto remaining = slice.length;
    while (segment != nullptr and remaining != 0) {
        auto const available = std::uint32_t{segment->data_len} - skip;
        auto const count = std::min(remaining, available);
        if (count != 0) {
            auto const* data = rte_pktmbuf_mtod(segment, unsigned char const*);
            consume(Bytes<>{data + skip, count});
            remaining -= count;
        }
        skip = 0;
        segment = segment->next;
    }
    return remaining == 0;
}

} // namespace protocol
