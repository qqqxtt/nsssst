#pragma once
#include "mbuf_slice.hpp"
#include <algorithm>
#include <stdexcept>
#include <vector>

// A frame split into three synthetic mbuf segments: bytes [0, cut) after 3 bytes of headroom,
// an empty segment, then the rest after 5 bytes of headroom. Exercises cross-segment reads,
// empty segments and non-zero data_off without EAL. Owns copies of the bytes.
class SplitFrame {
  public:
    SplitFrame(protocol::Bytes<> frame, std::size_t cut)
        : cut_(checked(frame, cut)), first_(cut + head_room),
          second_(frame.size() - cut + tail_room) {
        std::copy_n(frame.begin(), cut, first_.begin() + head_room);
        std::copy(frame.begin() + cut, frame.end(), second_.begin() + tail_room);
        head_.buf_addr = first_.data();
        head_.buf_len = static_cast<std::uint16_t>(first_.size());
        head_.data_off = head_room;
        head_.data_len = static_cast<std::uint16_t>(cut);
        head_.pkt_len = static_cast<std::uint32_t>(frame.size());
        head_.nb_segs = 3;
        head_.next = &empty_;
        empty_.buf_addr = first_.data();
        empty_.next = &tail_;
        tail_.buf_addr = second_.data();
        tail_.buf_len = static_cast<std::uint16_t>(second_.size());
        tail_.data_off = tail_room;
        tail_.data_len = static_cast<std::uint16_t>(frame.size() - cut);
        tail_.pkt_len = tail_.data_len;
        tail_.nb_segs = 1;
    }
    SplitFrame(SplitFrame const &) = delete; // Segments point at each other.
    SplitFrame &operator=(SplitFrame const &) = delete;

    rte_mbuf const &packet() const noexcept { return head_; }
    // Where frame byte `offset` lives in the chain: for zero-copy pointer identity checks.
    unsigned char const *address(std::size_t offset) const noexcept {
        return offset < cut_ ? first_.data() + head_room + offset
                             : second_.data() + tail_room + (offset - cut_);
    }
    // Mutable access to frame byte `offset` inside the chain, for corrupting fields in place.
    unsigned char &at(std::size_t offset) noexcept {
        return offset < cut_ ? first_[head_room + offset] : second_[tail_room + (offset - cut_)];
    }
    // Overwrites the packet bytes: views that still read packet memory would now see zeros.
    void clear() noexcept {
        std::fill(first_.begin(), first_.end(), 0);
        std::fill(second_.begin(), second_.end(), 0);
    }

  private:
    static std::size_t checked(protocol::Bytes<> frame, std::size_t cut) {
        if (cut > frame.size())
            throw std::out_of_range("SplitFrame cut beyond frame");
        return cut;
    }
    static constexpr std::uint16_t head_room = 3, tail_room = 5;
    std::size_t cut_;
    std::vector<unsigned char> first_, second_;
    rte_mbuf head_{}, empty_{}, tail_{};
};
