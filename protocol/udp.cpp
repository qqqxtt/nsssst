#include "udp.hpp"
#include "checksum.hpp"
#include "ethernet.hpp"

#include <algorithm>

namespace protocol {
namespace {
void write_u16(std::span<unsigned char> bytes, std::size_t offset, std::uint16_t value) {
    bytes[offset] = static_cast<unsigned char>(value >> 8);
    bytes[offset + 1] = static_cast<unsigned char>(value & 255);
}
std::array<unsigned char, 12> pseudo_header(Bytes<4> source, Bytes<4> destination,
                                            std::uint16_t length) {
    std::array<unsigned char, 12> header{};
    std::copy(source.begin(), source.end(), header.begin());
    std::copy(destination.begin(), destination.end(), header.begin() + 4);
    header[9] = IP_PROTOCOL_UDP;
    write_u16(header, 10, length);
    return header;
}
bool unicast_mac(Bytes<6> mac) {
    return (mac[0] & 1) == 0 and
           std::any_of(mac.begin(), mac.end(), [](auto byte) { return byte != 0; });
}
bool unicast_ip(Ipv4Address const &ip) {
    return ip[0] != 0 and ip[0] != 127 and ip[0] < 224;
}
} // namespace

std::optional<UdpView> UdpView::parse(IPv4View const &ip) {
    auto message = ip.payload();
    if (ip.protocol() != IP_PROTOCOL_UDP or message.length < UDP_HEADER_LENGTH) {
        return std::nullopt;
    }
    std::array<unsigned char, UDP_HEADER_LENGTH> scratch{};
    auto const *header = static_cast<unsigned char const *>(
        rte_pktmbuf_read(message.packet, message.offset, UDP_HEADER_LENGTH, scratch.data()));
    if (header == nullptr)
        return std::nullopt;
    std::array<unsigned char, UDP_HEADER_LENGTH> snapshot{};
    std::copy_n(header, snapshot.size(), snapshot.begin());
    UdpView result{snapshot, message};
    if (result.length() < UDP_HEADER_LENGTH or result.length() > message.length) {
        return std::nullopt;
    }
    message.length = result.length();
    // A zero UDP checksum means no checksum was provided, for IPv4 only.
    if (result.checksum() != 0) {
        InternetChecksum checksum;
        auto pseudo = pseudo_header(ip.source(), ip.destination(), result.length());
        checksum.add(pseudo);
        if (not for_each_chunk(message, [&](Bytes<> chunk) { checksum.add(chunk); }) or
            checksum.value() != 0) {
            return std::nullopt;
        }
    }
    result.payload_.offset += UDP_HEADER_LENGTH;
    result.payload_.length = result.length() - UDP_HEADER_LENGTH;
    return result;
}

namespace {
template <class Copy>
std::optional<std::vector<unsigned char>> build_reply(UdpReplyInfo const &info, std::size_t size,
                                                      Copy copy) {
    if (size > UDP_MTU - IPV4_HEADER_LENGTH - UDP_HEADER_LENGTH or info.source.port == 0 or
        info.destination.port == 0 or not unicast_mac(info.local_mac) or
        not unicast_mac(info.peer_mac) or not unicast_ip(info.source.address) or
        not unicast_ip(info.destination.address))
        return std::nullopt;
    auto const length = static_cast<std::uint16_t>(UDP_HEADER_LENGTH + size);
    auto const total = static_cast<std::uint16_t>(IPV4_HEADER_LENGTH + length);
    std::vector<unsigned char> frame(std::max<std::size_t>(60, ETHERNET_HEADER_LENGTH + total), 0);
    std::copy(info.peer_mac.begin(), info.peer_mac.end(), frame.begin());
    std::copy(info.local_mac.begin(), info.local_mac.end(), frame.begin() + 6);
    frame[12] = 8;
    auto ip = std::span<unsigned char>{frame}.subspan(14, 20);
    ip[0] = 0x45;
    write_u16(ip, 2, total);
    ip[6] = 0x40;
    ip[8] = 64;
    ip[9] = IP_PROTOCOL_UDP;
    std::copy(info.source.address.begin(), info.source.address.end(), ip.begin() + 12);
    std::copy(info.destination.address.begin(), info.destination.address.end(), ip.begin() + 16);
    write_u16(ip, 10, internet_checksum(Bytes<>{ip}));
    auto udp = std::span<unsigned char>{frame}.subspan(34, length);
    write_u16(udp, 0, info.source.port);
    write_u16(udp, 2, info.destination.port);
    write_u16(udp, 4, length);
    if (not copy(udp.subspan(UDP_HEADER_LENGTH)))
        return std::nullopt;
    InternetChecksum checksum;
    checksum.add(pseudo_header(info.source.address, info.destination.address, length));
    checksum.add(Bytes<>{udp});
    auto value = checksum.value();
    write_u16(udp, 6, value == 0 ? 0xffff : value);
    return frame;
}
} // namespace
std::optional<std::vector<unsigned char>> build_udp_reply(UdpReplyInfo const &info,
                                                          Bytes<> payload) {
    return build_reply(info, payload.size(), [&](std::span<unsigned char> out) {
        std::copy(payload.begin(), payload.end(), out.begin());
        return true;
    });
}
std::optional<std::vector<unsigned char>> build_udp_reply(UdpReplyInfo const &info,
                                                          PacketSlice const &payload) {
    return build_reply(info, payload.length, [&](std::span<unsigned char> out) {
        std::size_t copied{};
        return for_each_chunk(payload, [&](Bytes<> chunk) {
            std::copy(chunk.begin(), chunk.end(), out.begin() + copied);
            copied += chunk.size();
        });
    });
}
} // namespace protocol
