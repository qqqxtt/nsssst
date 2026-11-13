#pragma once
#include "mbuf_slice.hpp"
#include <memory>
namespace protocol {
struct PacketRefDeleter {
    void operator()(rte_mbuf *p) const noexcept { rte_pktmbuf_free(p); }
};
// One owned intrusive reference to every segment. Shared chain/data must stay immutable.
using PacketRef = std::unique_ptr<rte_mbuf, PacketRefDeleter>;
inline PacketRef retain_packet(rte_mbuf const &packet) {
    auto *p = const_cast<rte_mbuf *>(&packet); // Only reference-count metadata is modified.
    rte_pktmbuf_refcnt_update(p, 1);
    return PacketRef{p};
}
struct RetainedSlice {
    PacketRef owner;
    std::uint32_t offset{}, length{};
    PacketSlice view() const { return {owner.get(), offset, length}; }
};
} // namespace protocol
