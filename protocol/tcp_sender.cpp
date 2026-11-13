#include "checksum.hpp"
#include "tcp_manager.hpp"
#include <algorithm>
#include <array>
#include <stdexcept>
namespace protocol {
namespace {
constexpr std::uint32_t window = 32768;
void put(std::span<unsigned char> b, unsigned off, std::uint32_t n, unsigned count) {
    for (unsigned i = 0; i < count; ++i)
        b[off + i] = static_cast<unsigned char>(n >> (8 * (count - i - 1)));
}
} // namespace
void TcpManager::send(Key const &key, Session const &s, std::uint8_t flags, std::uint32_t seq,
                      Bytes<> payload) {
    // Stack buffer: no heap allocation per segment. Payload is bounded by the MSS (<= 536).
    std::array<unsigned char, 1514> buffer;
    if (payload.size() > buffer.size() - 54)
        throw std::length_error("TCP segment exceeds Ethernet MTU");
    auto const size = std::max<std::size_t>(60, 54 + payload.size());
    std::fill_n(buffer.begin(), size, 0);
    auto frame = std::span<unsigned char>{buffer}.first(size);
    std::copy(s.mac.begin(), s.mac.end(), frame.begin());
    std::copy(local_.mac.begin(), local_.mac.end(), frame.begin() + 6);
    frame[12] = 8;
    auto ip = frame.subspan(14, 20);
    ip[0] = 0x45;
    put(ip, 2, 40 + payload.size(), 2);
    ip[8] = 64;
    ip[9] = 6;
    std::copy(local_.ip.begin(), local_.ip.end(), ip.begin() + 12);
    std::copy(key.peer.begin(), key.peer.end(), ip.begin() + 16);
    put(ip, 10, internet_checksum(ip), 2);
    auto tcp = frame.subspan(34, 20 + payload.size());
    put(tcp, 0, key.local_port, 2);
    put(tcp, 2, key.peer_port, 2);
    put(tcp, 4, seq, 4);
    put(tcp, 8, (flags & 0x10) ? static_cast<std::uint32_t>(s.next) : 0, 4);
    tcp[12] = 0x50;
    tcp[13] = flags;
    put(tcp, 14, window, 2);
    std::array<unsigned char, 12> pseudo{};
    std::copy(local_.ip.begin(), local_.ip.end(), pseudo.begin());
    std::copy(key.peer.begin(), key.peer.end(), pseudo.begin() + 4);
    pseudo[9] = 6;
    put(pseudo, 10, tcp.size(), 2);
    std::copy(payload.begin(), payload.end(), tcp.begin() + 20);
    InternetChecksum sum;
    sum.add(pseudo);
    sum.add(tcp);
    put(tcp, 16, sum.value(), 2);
    if (flags & 0x10)
        s.ack_pending = false;
    sender_(frame); // Control segments remain scheduled even when TX rejects this attempt.
}
} // namespace protocol
