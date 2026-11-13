#pragma once
#include <array>
#include <cstddef>
#include <span>
#include <stdexcept>
#include <utility>

namespace dpdk {
// Owns packets until the sender accepts a prefix. Full queues consume/release rejected packets.
template <class Packet, std::size_t Capacity> class PendingTx {
  public:
    bool push(Packet packet) noexcept {
        if (!packet || size_ == Capacity)
            return false;
        packets_[size_++] = std::move(packet);
        return true;
    }
    std::size_t size() const noexcept { return size_; }
    bool full() const noexcept { return size_ == Capacity; }
    template <class Sender> std::size_t flush(Sender &&send) {
        if (!size_)
            return 0;
        std::array<typename Packet::pointer, Capacity> raw;
        for (std::size_t i = 0; i < size_; ++i)
            raw[i] = packets_[i].get();
        auto accepted = std::size_t(send(std::span{raw.data(), size_}));
        if (accepted > size_)
            throw std::logic_error("TX accepted more packets than submitted");
        if (!accepted)
            return 0;
        for (std::size_t i = 0; i < accepted; ++i)
            (void)packets_[i].release();
        for (std::size_t i = accepted; i < size_; ++i)
            packets_[i - accepted] = std::move(packets_[i]);
        size_ -= accepted;
        return accepted;
    }
    PendingTx() = default;
    PendingTx(PendingTx const &) = delete;
    PendingTx &operator=(PendingTx const &) = delete;

  private:
    std::array<Packet, Capacity> packets_{};
    std::size_t size_{};
};
} // namespace dpdk
