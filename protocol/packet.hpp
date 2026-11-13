#pragma once

#include <cstddef>
#include <span>
#include <type_traits>

namespace protocol {

template<std::size_t N = std::dynamic_extent>
using Bytes = std::span<const unsigned char, N>;

}