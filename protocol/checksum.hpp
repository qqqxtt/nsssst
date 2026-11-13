#pragma once

#include "mbuf_slice.hpp"

#include <bit>
#include <cstdint>
#include <cstring>
#include <optional>

namespace protocol {

// Incremental Internet checksum. Byte pairing continues across add() calls.
// An odd final byte is treated as the high byte of a word with a zero low byte.
// Bulk data is summed as native 32-bit words and byte-swapped once (RFC 1071 byte-order
// independence), instead of folding after every byte.
class InternetChecksum {
  public:
    void add(Bytes<> bytes) noexcept {
        auto const *p = bytes.data();
        auto n = bytes.size();
        if (n == 0)
            return;
        if (not high_byte_) { // Complete the word started by the previous call.
            sum_ += *p++;
            --n;
            high_byte_ = true;
        }
        std::uint64_t acc{};
        for (; n >= 8; p += 8, n -= 8) {
            std::uint32_t a, b;
            std::memcpy(&a, p, 4);
            std::memcpy(&b, p + 4, 4);
            acc += a;
            acc += b;
        }
        if (n >= 4) {
            std::uint32_t a;
            std::memcpy(&a, p, 4);
            acc += a;
            p += 4;
            n -= 4;
        }
        if (n >= 2) {
            std::uint16_t a;
            std::memcpy(&a, p, 2);
            acc += a;
            p += 2;
            n -= 2;
        }
        auto word = static_cast<std::uint16_t>(fold(acc));
        if constexpr (std::endian::native == std::endian::little)
            word = static_cast<std::uint16_t>((word >> 8) | (word << 8));
        sum_ += word;
        if (n) {
            sum_ += std::uint64_t{*p} << 8;
            high_byte_ = false;
        }
    }
    std::uint16_t value() const noexcept { return static_cast<std::uint16_t>(~fold(sum_)); }

  private:
    static std::uint64_t fold(std::uint64_t v) noexcept {
        while (v >> 16)
            v = (v & 0xffff) + (v >> 16);
        return v;
    }
    std::uint64_t sum_{};
    bool high_byte_{true};
};

inline std::uint16_t internet_checksum(Bytes<> bytes) noexcept {
    InternetChecksum checksum;
    checksum.add(bytes);
    return checksum.value();
}

inline std::optional<std::uint16_t> internet_checksum(PacketSlice const& slice) {
    InternetChecksum checksum;
    if (not for_each_chunk(slice, [&](Bytes<> bytes) { checksum.add(bytes); })) {
        return std::nullopt;
    }
    return checksum.value();
}

} // namespace protocol
