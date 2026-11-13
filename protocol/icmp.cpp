#include "icmp.hpp"
#include "checksum.hpp"
#include "ethernet.hpp"

#include <algorithm>

namespace protocol {

std::optional<ICMPEchoView> ICMPEchoView::parse(PacketSlice const &message) {
    if (message.packet == nullptr or message.offset > message.packet->pkt_len or
        message.length > message.packet->pkt_len - message.offset or
        message.length < ICMP_ECHO_HEADER_LENGTH or message.length > 65535 - IPV4_HEADER_LENGTH) {
        return std::nullopt;
    }
    std::array<unsigned char, ICMP_ECHO_HEADER_LENGTH> scratch{};
    auto const *header = static_cast<unsigned char const *>(
        rte_pktmbuf_read(message.packet, message.offset, ICMP_ECHO_HEADER_LENGTH, scratch.data()));
    if (header == nullptr or header[1] != 0 or (header[0] != 0 and header[0] != 8)) {
        return std::nullopt;
    }
    auto const checksum = internet_checksum(message);
    if (not checksum or *checksum != 0) {
        return std::nullopt;
    }
    std::array<unsigned char, ICMP_ECHO_HEADER_LENGTH> snapshot{};
    std::copy_n(header, snapshot.size(), snapshot.begin());
    return ICMPEchoView{snapshot,
                        {message.packet, message.offset + ICMP_ECHO_HEADER_LENGTH,
                         message.length - ICMP_ECHO_HEADER_LENGTH}};
}

namespace {
void write_u16(std::span<unsigned char> bytes, std::size_t offset, std::uint16_t value) {
    bytes[offset] = static_cast<unsigned char>(value >> 8);
    bytes[offset + 1] = static_cast<unsigned char>(value & 255);
}
bool unicast_mac(Bytes<6> mac) {
    return (mac[0] & 1) == 0 and
           std::any_of(mac.begin(), mac.end(), [](auto byte) { return byte != 0; });
}
} // namespace

std::optional<std::vector<unsigned char>>
build_icmp_echo_reply(IPv4View const &request, Bytes<6> local_mac, Bytes<6> peer_mac) {
    if (request.protocol() != IP_PROTOCOL_ICMP or request.total_length() > ICMP_ECHO_MTU or
        not unicast_mac(local_mac) or not unicast_mac(peer_mac) or request.source()[0] == 0 or
        request.source()[0] == 127 or request.source()[0] >= 224) {
        return std::nullopt;
    }
    auto const echo = ICMPEchoView::parse(request.payload());
    if (not echo or echo->type() != IcmpEchoType::Request) {
        return std::nullopt;
    }

    std::vector<unsigned char> frame(
        std::max<std::size_t>(60, ETHERNET_HEADER_LENGTH + request.total_length()), 0);
    std::copy(peer_mac.begin(), peer_mac.end(), frame.begin());
    std::copy(local_mac.begin(), local_mac.end(), frame.begin() + 6);
    frame[12] = 8; // EtherType = IPv4
    auto ip = std::span<unsigned char>{frame}.subspan(ETHERNET_HEADER_LENGTH, IPV4_HEADER_LENGTH);
    ip[0] = 0x45;
    write_u16(ip, 2, request.total_length());
    ip[6] = 0x40; // DF=1; atomic datagram ID=0
    ip[8] = 64;
    ip[9] = IP_PROTOCOL_ICMP;
    std::copy(request.destination().begin(), request.destination().end(), ip.begin() + 12);
    std::copy(request.source().begin(), request.source().end(), ip.begin() + 16);
    write_u16(ip, 10, internet_checksum(Bytes<>{ip}));

    auto icmp = std::span<unsigned char>{frame}.subspan(ETHERNET_HEADER_LENGTH + IPV4_HEADER_LENGTH,
                                                        request.payload().length);
    // Type=0 (Reply), Code=0 and checksum initially zero.
    write_u16(icmp, 4, echo->identifier());
    write_u16(icmp, 6, echo->sequence());
    std::size_t copied = ICMP_ECHO_HEADER_LENGTH;
    if (not for_each_chunk(echo->payload(), [&](Bytes<> chunk) {
            std::copy(chunk.begin(), chunk.end(), icmp.begin() + copied);
            copied += chunk.size();
        })) {
        return std::nullopt;
    }
    write_u16(icmp, 2, internet_checksum(Bytes<>{icmp}));
    return frame;
}

} // namespace protocol
