#include "kernel_resolver.hpp"
#include <algorithm>
#include <cstring>
#include <memory>
#include <netdb.h>
#include <stdexcept>
namespace binance {
std::vector<protocol::Ipv4Address> resolve_ipv4(std::string const &hostname) {
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo *raw{};
    auto error = getaddrinfo(hostname.c_str(), nullptr, &hints, &raw);
    if (error)
        throw std::runtime_error(gai_strerror(error));
    std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> result(raw, freeaddrinfo);
    std::vector<protocol::Ipv4Address> addresses;
    for (auto *p = raw; p; p = p->ai_next) {
        protocol::Ipv4Address ip{};
        std::memcpy(ip.data(), &reinterpret_cast<sockaddr_in const *>(p->ai_addr)->sin_addr, 4);
        if (std::find(addresses.begin(), addresses.end(), ip) == addresses.end())
            addresses.push_back(ip);
    }
    if (addresses.empty())
        throw std::runtime_error("DNS returned no IPv4 address");
    return addresses;
}
} // namespace net
