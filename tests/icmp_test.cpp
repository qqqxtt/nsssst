#include "checksum.hpp"
#include "ethernet.hpp"
#include "icmp.hpp"
#include "mbuf_chain.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <stdexcept>
#include <vector>

namespace {
void expect(bool ok, char const *message) {
    if (not ok)
        throw std::runtime_error(message);
}

// Independent word-oriented oracle; no production checksum helper used here.
std::uint16_t reference(protocol::Bytes<> bytes) {
    std::uint64_t sum{};
    for (std::size_t i = 0; i < bytes.size(); i += 2) {
        sum += std::uint64_t{bytes[i]} * 256;
        if (i + 1 < bytes.size())
            sum += bytes[i + 1];
    }
    while (sum > 65535)
        sum = (sum & 65535) + (sum >> 16);
    return static_cast<std::uint16_t>(sum ^ 65535);
}
void write(std::span<unsigned char> bytes, std::size_t offset, std::uint16_t value) {
    bytes[offset] = static_cast<unsigned char>(value >> 8);
    bytes[offset + 1] = static_cast<unsigned char>(value & 255);
}
void repair(std::vector<unsigned char> &frame) {
    auto bytes = std::span<unsigned char>{frame};
    auto total = std::size_t{bytes[16]} * 256 + bytes[17];
    auto ip = bytes.subspan(14, 20);
    auto icmp = bytes.subspan(34, total - 20);
    write(ip, 10, 0);
    write(ip, 10, reference(ip));
    write(icmp, 2, 0);
    write(icmp, 2, reference(icmp));
}
std::vector<unsigned char> request(std::size_t size) {
    std::vector<unsigned char> frame(std::max<std::size_t>(60, 42 + size), 0);
    frame[0] = frame[6] = 2;
    frame[5] = 2;
    frame[11] = 1;
    frame[12] = 8;
    frame[14] = 0x45;
    write(frame, 16, static_cast<std::uint16_t>(28 + size));
    frame[20] = 0x40;
    frame[22] = 63;
    frame[23] = 1;
    frame[26] = frame[30] = 192;
    frame[28] = frame[32] = 2;
    frame[29] = 1;
    frame[33] = 2;
    frame[34] = 8;
    write(frame, 38, 0x1234);
    write(frame, 40, 0xabcd);
    for (std::size_t i = 0; i < size; ++i)
        frame[42 + i] = static_cast<unsigned char>(i * 37);
    repair(frame);
    return frame;
}

template <class Fn>
void with_chain(std::vector<unsigned char> const &frame, std::size_t cut, Fn fn) {
    SplitFrame chain{frame, cut};
    fn(chain.packet());
}
void check_reply(std::size_t size, std::size_t cut) {
    auto frame = request(size);
    auto original = frame;
    with_chain(frame, cut, [&](rte_mbuf const &packet) {
        auto ethernet = protocol::EthernetView::parse(packet);
        expect(ethernet.has_value(), "Ethernet parse");
        auto ip = protocol::IPv4View::parse(ethernet->payload());
        expect(ip.has_value(), "IPv4 parse");
        auto echo = protocol::ICMPEchoView::parse(ip->payload());
        expect(echo and echo->identifier() == 0x1234 and echo->sequence() == 0xabcd, "Echo fields");
        expect(echo->payload().offset == 42 and echo->payload().length == size,
               "Echo payload bounds");
        auto reply =
            protocol::build_icmp_echo_reply(*ip, ethernet->destination(), ethernet->source());
        expect(reply and reply->size() == frame.size(), "Echo reply size");
        expect(std::equal(reply->begin(), reply->begin() + 6, frame.begin() + 6),
               "destination MAC");
        expect(std::equal(reply->begin() + 6, reply->begin() + 12, frame.begin()), "source MAC");
        expect(std::equal(reply->begin() + 26, reply->begin() + 30, frame.begin() + 30),
               "source IP");
        expect(std::equal(reply->begin() + 30, reply->begin() + 34, frame.begin() + 26),
               "destination IP");
        expect((*reply)[22] == 64 and (*reply)[34] == 0 and (*reply)[35] == 0, "TTL/type/code");
        expect(std::equal(reply->begin() + 38, reply->begin() + 42 + size, frame.begin() + 38),
               "identifier/sequence/data must be unchanged");
        expect(reference(protocol::Bytes<>{*reply}.subspan(14, 20)) == 0, "reply IPv4 checksum");
        expect(reference(protocol::Bytes<>{*reply}.subspan(34, 8 + size)) == 0,
               "reply ICMP checksum");
        expect(std::all_of(reply->begin() + 42 + size, reply->end(), [](auto b) { return b == 0; }),
               "zero padding");
        with_chain(*reply, 39, [&](rte_mbuf const &response) {
            auto reply_ip = protocol::IPv4View::parse({&response, 14, response.pkt_len - 14});
            expect(reply_ip.has_value(), "response IPv4 parse");
            auto reply_echo = protocol::ICMPEchoView::parse(reply_ip->payload());
            expect(reply_echo and reply_echo->type() == protocol::IcmpEchoType::Reply,
                   "response type");
            expect(not protocol::build_icmp_echo_reply(*reply_ip, ethernet->source(),
                                                       ethernet->destination()),
                   "never reply to reply");
        });
    });
    expect(frame == original, "RX data must not be modified");
}
void check_checksum() {
    std::array<unsigned char, 8> known{0, 1, 0xf2, 3, 0xf4, 0xf5, 0xf6, 0xf7};
    expect(protocol::internet_checksum(known) == 0x220d, "known checksum vector");
    std::vector<unsigned char> data(131077, 255); // exceeds a naive uint32 accumulator
    expect(protocol::internet_checksum(data) == reference(data), "checksum accumulator overflow");
    for (std::size_t size = 0; size < 100; ++size) {
        for (std::size_t i = 0; i < size; ++i)
            data[i] = static_cast<unsigned char>(i * 19);
        auto bytes = protocol::Bytes<>{data}.first(size);
        for (std::size_t cut = 0; cut <= size; ++cut) {
            protocol::InternetChecksum checksum;
            checksum.add(bytes.first(cut));
            checksum.add({});
            checksum.add(bytes.subspan(cut));
            expect(checksum.value() == reference(bytes), "checksum split/odd byte");
            expect(checksum.value() == reference(bytes), "value must not mutate accumulator");
        }
    }
}
void check_invalid() {
    auto check_bad = [](std::vector<unsigned char> const &frame) {
        with_chain(frame, 37, [&](rte_mbuf const &packet) {
            auto ip = protocol::IPv4View::parse({&packet, 14, packet.pkt_len - 14});
            expect(ip.has_value(), "invalid test IP header");
            expect(not protocol::ICMPEchoView::parse(ip->payload()), "invalid ICMP accepted");
            constexpr std::array<unsigned char, 6> a{2, 0, 0, 0, 0, 2}, b{2, 0, 0, 0, 0, 1};
            expect(not protocol::build_icmp_echo_reply(*ip, a, b), "invalid ICMP replied");
        });
    };
    auto frame = request(5);
    frame[42] ^= 1;
    check_bad(frame);
    frame = request(5);
    frame[34] = 3;
    repair(frame);
    check_bad(frame);
    frame = request(5);
    frame[35] = 1;
    repair(frame);
    check_bad(frame);
    frame = request(5);
    write(frame, 16, 27);
    repair(frame);
    check_bad(frame);
    frame = request(1473);
    with_chain(frame, 41, [&](rte_mbuf const &packet) {
        auto ip = protocol::IPv4View::parse({&packet, 14, packet.pkt_len - 14});
        constexpr std::array<unsigned char, 6> a{2, 0, 0, 0, 0, 2}, b{2, 0, 0, 0, 0, 1};
        expect(ip and not protocol::build_icmp_echo_reply(*ip, a, b), "MTU limit");
    });
    frame = request(5);
    with_chain(frame, 40, [&](rte_mbuf const &packet) {
        expect(not protocol::ICMPEchoView::parse({}), "null slice");
        expect(not protocol::ICMPEchoView::parse({&packet, 34, 7}), "short slice");
        expect(not protocol::ICMPEchoView::parse({&packet, 0xffffffffU, 8}), "invalid offset");
        expect(not protocol::ICMPEchoView::parse({&packet, 34, packet.pkt_len}), "invalid length");
    });
}
} // namespace
int main() {
    try {
        check_checksum();
        for (std::size_t size : {0, 1, 5, 56}) {
            auto frame = request(size);
            for (std::size_t cut = 0; cut <= frame.size(); ++cut)
                check_reply(size, cut);
        }
        for (std::size_t cut : {0, 33, 34, 39, 40, 41, 42, 43, 1514})
            check_reply(1472, cut);
        check_invalid();
        std::puts("PASS: checksum splits, ICMP fields, odd/empty data, replies, malformed inputs "
                  "and MTU");
        return 0;
    } catch (std::exception const &error) {
        std::fprintf(stderr, "%s\n", error.what());
        return 1;
    }
}
