#include "ethernet.hpp"
#include "ipv4.hpp"
#include "mbuf_chain.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <stdexcept>

namespace {
void expect(bool ok, char const *message) {
    if (not ok)
        throw std::runtime_error(message);
}

// Known header checksum is 0xb861; Total Length=115, Protocol=UDP, DF=1.
constexpr std::array<unsigned char, 20> HEADER{0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40,
                                               0x00, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8,
                                               0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7};
using Frame = std::array<unsigned char, 136>;

Frame make_frame() {
    Frame frame{};
    std::fill_n(frame.begin(), 6, 255);
    frame[6] = 2;
    frame[12] = 8;
    std::copy(HEADER.begin(), HEADER.end(), frame.begin() + 14);
    for (std::size_t i = 34; i < 129; ++i)
        frame[i] = static_cast<unsigned char>(i);
    std::fill(frame.begin() + 129, frame.end(), 0xee); // trailing Ethernet bytes
    return frame;
}

void check_fields(protocol::IPv4View const &ip) {
    expect(ip.version() == 4 and ip.header_length() == 20, "version/IHL");
    expect(ip.dscp() == 0 and ip.ecn() == 0, "DSCP/ECN");
    expect(ip.identification() == 0 and ip.dont_fragment(), "ID/DF");
    expect(ip.ttl() == 64 and ip.protocol() == 17, "TTL/protocol");
    expect(ip.header_checksum() == 0xb861 and ip.total_length() == 115, "checksum/length");
    constexpr std::array<unsigned char, 4> source{192, 168, 0, 1}, destination{192, 168, 0, 199};
    expect(std::equal(ip.source().begin(), ip.source().end(), source.begin()), "source IP");
    expect(std::equal(ip.destination().begin(), ip.destination().end(), destination.begin()),
           "destination IP");
}

void check_all_cuts() {
    auto const frame = make_frame();
    for (std::size_t cut = 0; cut <= frame.size(); ++cut) {
        SplitFrame chain{frame, cut};
        auto const &head = chain.packet();

        auto ethernet = protocol::EthernetView::parse(head);
        expect(ethernet.has_value(), "Ethernet parse");
        expect(ethernet->ether_type() == 0x0800, "IPv4 EtherType");
        auto ip = protocol::IPv4View::parse(ethernet->payload());
        expect(ip.has_value(), "cross-mbuf parse");
        check_fields(*ip);
        auto payload = ip->payload();
        expect(payload.packet == &head and payload.offset == 34 and payload.length == 95,
               "payload excludes trailing bytes");
        std::size_t seen{};
        expect(protocol::for_each_chunk(
                   payload,
                   [&](auto bytes) {
                       auto offset = 34 + seen;
                       expect(bytes.data() == chain.address(offset),
                              "payload must reference original storage");
                       expect(std::equal(bytes.begin(), bytes.end(), frame.begin() + offset),
                              "payload data");
                       seen += bytes.size();
                   }),
               "payload iteration");
        expect(seen == 95, "payload length");
        chain.clear();
        check_fields(*ip); // snapshot is independent of packet memory
    }
}

// Test-only checksum writer, independent of the parser's validation path.
void checksum(Frame &frame) {
    frame[24] = 0;
    frame[25] = 0;
    unsigned sum{};
    for (std::size_t i = 14; i < 34; i += 2)
        sum += unsigned(frame[i]) * 256 + frame[i + 1];
    sum = (sum & 65535) + (sum >> 16);
    sum = (sum & 65535) + (sum >> 16);
    auto result = static_cast<std::uint16_t>(~sum);
    frame[24] = static_cast<unsigned char>(result >> 8);
    frame[25] = static_cast<unsigned char>(result & 255);
}

void check_boundaries() {
    auto frame = make_frame();
    rte_mbuf packet{};
    packet.buf_addr = frame.data();
    packet.buf_len = frame.size();
    packet.data_len = frame.size();
    packet.pkt_len = frame.size();
    packet.nb_segs = 1;
    auto parse = [&] { return protocol::IPv4View::parse({&packet, 14, packet.pkt_len - 14}); };
    expect(not protocol::IPv4View::parse({}), "null packet");
    expect(not protocol::IPv4View::parse({&packet, 137, 20}), "offset outside packet");
    expect(not protocol::IPv4View::parse({&packet, 0xffffffffU, 20}), "overflowing offset");
    expect(not protocol::IPv4View::parse({&packet, 14, 123}), "slice exceeds packet");
    expect(not protocol::IPv4View::parse({&packet, 14, 20}),
           "IP exceeds slice despite backing bytes");
    for (std::uint16_t length = 0; length < 115; ++length) {
        packet.pkt_len = 14 + length;
        packet.data_len = static_cast<std::uint16_t>(packet.pkt_len);
        expect(not parse(), "truncated header or payload");
    }
    packet.pkt_len = frame.size();
    packet.data_len = frame.size();
    auto reject = [&](std::size_t offset, unsigned char value) {
        frame = make_frame();
        frame[14 + offset] = value;
        checksum(frame);
        expect(not parse(), "invalid IPv4 field accepted");
    };
    reject(0, 0x65); // version
    reject(0, 0x44); // IHL too short
    reject(0, 0x46); // options unsupported
    reject(3, 19);   // total length shorter than header
    reject(2, 1);    // total length exceeds available bytes
    reject(6, 0x60); // MF (including first fragment)
    reject(7, 1);    // non-first fragment
    reject(6, 0x80); // reserved flag
    frame = make_frame();
    frame[18] ^= 1;
    expect(not parse(), "invalid header checksum accepted");
    frame = make_frame();
    frame[34] ^= 1;
    expect(parse().has_value(), "IP checksum covers header only");
    for (unsigned char protocol : {1, 6, 17, 99}) {
        frame = make_frame();
        frame[23] = protocol;
        checksum(frame);
        expect(parse().has_value(), "IPv4 parser must not require UDP");
    }
    // An endpoint must not reject a local datagram solely for TTL < 2 (RFC 1122).
    for (unsigned char ttl : {0, 1}) {
        frame = make_frame();
        frame[22] = ttl;
        checksum(frame);
        auto ip = parse();
        expect(ip and ip->ttl() == ttl, "low TTL at receiving endpoint");
    }
    frame = make_frame();
    frame[15] = 0xab;
    frame[20] = 0;
    checksum(frame);
    auto fields = parse();
    expect(fields and fields->dscp() == 42 and fields->ecn() == 3 and not fields->dont_fragment(),
           "DSCP/ECN and DF=0");
    frame = make_frame();
    frame[17] = 20;
    checksum(frame);
    auto empty = parse();
    expect(empty and empty->payload().length == 0, "empty payload");
    expect(protocol::for_each_chunk(
               empty->payload(), [](auto) { throw std::runtime_error("empty payload callback"); }),
           "empty payload iteration");
}
} // namespace

int main() {
    try {
        check_all_cuts();
        check_boundaries();
        std::puts(
            "PASS: IPv4 fields, all 137 cuts, bounds, checksum, padding and fragment rejection");
        return 0;
    } catch (std::exception const &error) {
        std::fprintf(stderr, "%s\n", error.what());
        return 1;
    }
}
