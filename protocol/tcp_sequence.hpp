#pragma once
#include <cstdint>
namespace protocol {
inline std::uint64_t unwrap(std::uint32_t seq, std::uint64_t next) {
    auto delta = seq - static_cast<std::uint32_t>(next);
    return delta < 0x80000000U ? next + delta : next - (std::uint64_t{0x100000000ULL} - delta);
}
} // namespace protocol
