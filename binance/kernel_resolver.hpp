#pragma once
#include "address.hpp"
#include <string>
#include <vector>
namespace binance {
// Blocking libc getaddrinfo for IPv4; called from a background task, never the RX loop.
std::vector<protocol::Ipv4Address> resolve_ipv4(std::string const &hostname);
}
