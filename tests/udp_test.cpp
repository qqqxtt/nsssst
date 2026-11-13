#include "checksum.hpp"
#include "ethernet.hpp"
#include "udp.hpp"
#include "udp_registry.hpp"
#include "mbuf_chain.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <stdexcept>
#include <vector>

namespace {
using Frame = std::vector<unsigned char>;
constexpr std::array<unsigned char, 6> LOCAL{2, 0, 0, 0, 0, 2}, PEER{2, 0, 0, 0, 0, 1};
void expect(bool ok, char const *message) {
    if (not ok)
        throw std::runtime_error(message);
}
std::uint16_t read(protocol::Bytes<> bytes, std::size_t offset) {
    return static_cast<std::uint16_t>(unsigned(bytes[offset]) * 256 + bytes[offset + 1]);
}
void write(std::span<unsigned char> bytes, std::size_t offset, std::uint16_t value) {
    bytes[offset] = static_cast<unsigned char>(value >> 8);
    bytes[offset + 1] = static_cast<unsigned char>(value & 255);
}
// Independent word-oriented checksum oracle.
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
std::uint16_t udp_reference(Frame const &frame) {
    Frame pseudo(frame.begin() + 26, frame.begin() + 34);
    pseudo.push_back(0);
    pseudo.push_back(17);
    auto length = read(frame, 38);
    pseudo.push_back(static_cast<unsigned char>(length >> 8));
    pseudo.push_back(static_cast<unsigned char>(length & 255));
    pseudo.insert(pseudo.end(), frame.begin() + 34, frame.begin() + 34 + length);
    return reference(pseudo);
}
void repair_ip(Frame &frame) {
    write(frame, 24, 0);
    write(frame, 24, reference(protocol::Bytes<>{frame}.subspan(14, 20)));
}
void repair(Frame &frame, bool with_checksum = true) {
    repair_ip(frame);
    write(frame, 40, 0);
    if (with_checksum) {
        auto checksum = udp_reference(frame);
        write(frame, 40, checksum == 0 ? 0xffff : checksum);
    }
}
Frame request(std::size_t size, bool with_checksum = true, std::size_t extra = 0) {
    Frame frame(std::max<std::size_t>(60, 42 + size + extra), 0);
    std::copy(LOCAL.begin(), LOCAL.end(), frame.begin());
    std::copy(PEER.begin(), PEER.end(), frame.begin() + 6);
    frame[12] = 8;
    frame[14] = 0x45;
    write(frame, 16, static_cast<std::uint16_t>(28 + size + extra));
    frame[20] = 0x40;
    frame[22] = 63;
    frame[23] = 17;
    frame[26] = frame[30] = 192;
    frame[28] = frame[32] = 2;
    frame[29] = 1;
    frame[33] = 2;
    write(frame, 34, 40000);
    write(frame, 36, 19000);
    write(frame, 38, static_cast<std::uint16_t>(8 + size));
    for (std::size_t i = 0; i < size; ++i)
        frame[42 + i] = static_cast<unsigned char>(i * 37);
    std::fill(frame.begin() + 42 + size, frame.end(), 0xee); // IP trailing bytes / Ethernet padding
    repair(frame, with_checksum);
    return frame;
}

template <class Fn> void with_chain(Frame const &frame, std::size_t cut, Fn fn) {
    SplitFrame chain{frame, cut};
    fn(chain.packet(), chain);
}
auto reply_for(protocol::IPv4View const &ip, protocol::Bytes<6> local, protocol::Bytes<6> peer) {
    auto udp = protocol::UdpView::parse(ip);
    if (not udp)
        return std::optional<Frame>{};
    protocol::UdpReplyInfo info{};
    std::copy(ip.destination().begin(), ip.destination().end(), info.source.address.begin());
    std::copy(ip.source().begin(), ip.source().end(), info.destination.address.begin());
    std::copy(local.begin(), local.end(), info.local_mac.begin());
    std::copy(peer.begin(), peer.end(), info.peer_mac.begin());
    info.source.port = udp->destination_port();
    info.destination.port = udp->source_port();
    return protocol::build_udp_reply(info, udp->payload());
}
void check_echo(std::size_t size, std::size_t cut, bool checksum = true, std::size_t extra = 0) {
    auto frame = request(size, checksum, extra);
    auto original = frame;
    with_chain(frame, cut, [&](rte_mbuf const &packet, SplitFrame &chain) {
        auto ip = protocol::IPv4View::parse({&packet, 14, packet.pkt_len - 14});
        expect(ip.has_value(), "request IPv4");
        auto udp = protocol::UdpView::parse(*ip);
        expect(udp and udp->source_port() == 40000 and udp->destination_port() == 19000,
               "UDP ports");
        expect(udp->length() == 8 + size and udp->payload().length == size and
                   udp->payload().offset == 42,
               "UDP length");
        expect(checksum ? udp->checksum() != 0 : udp->checksum() == 0, "checksum presence");
        std::size_t seen{};
        expect(protocol::for_each_chunk(
                   udp->payload(),
                   [&](auto bytes) {
                       auto offset = 42 + seen;
                       expect(bytes.data() == chain.address(offset), "payload pointer identity");
                       expect(std::equal(bytes.begin(), bytes.end(), frame.begin() + offset),
                              "payload bytes");
                       seen += bytes.size();
                   }),
               "payload iteration");
        expect(seen == size, "payload count");
        auto reply = reply_for(*ip, LOCAL, PEER);
        expect(reply and reply->size() == std::max<std::size_t>(60, 42 + size), "reply size");
        expect(std::equal(reply->begin(), reply->begin() + 6, PEER.begin()), "destination MAC");
        expect(std::equal(reply->begin() + 6, reply->begin() + 12, LOCAL.begin()), "source MAC");
        expect(std::equal(reply->begin() + 26, reply->begin() + 30, frame.begin() + 30),
               "source IP");
        expect(std::equal(reply->begin() + 30, reply->begin() + 34, frame.begin() + 26),
               "destination IP");
        expect(read(*reply, 16) == 28 + size and (*reply)[22] == 64 and (*reply)[23] == 17,
               "reply IPv4 fields");
        expect(read(*reply, 34) == 19000 and read(*reply, 36) == 40000 and
                   read(*reply, 38) == 8 + size,
               "reply UDP fields");
        expect(read(*reply, 40) != 0 and udp_reference(*reply) == 0, "reply UDP checksum");
        expect(reference(protocol::Bytes<>{*reply}.subspan(14, 20)) == 0, "reply IP checksum");
        expect(std::equal(reply->begin() + 42, reply->begin() + 42 + size, frame.begin() + 42),
               "echo data");
        expect(std::all_of(reply->begin() + 42 + size, reply->end(), [](auto b) { return b == 0; }),
               "zero padding");
        chain.clear();
        expect(udp->source_port() == 40000 and udp->length() == 8 + size, "owned header snapshot");
    });
    expect(frame == original, "RX mutation");
}
void check_rejections() {
    auto validate = [](Frame const &frame, bool parse_ok, bool echo_ok) {
        with_chain(frame, 39, [&](rte_mbuf const &packet, SplitFrame &) {
            auto ip = protocol::IPv4View::parse({&packet, 14, packet.pkt_len - 14});
            expect(ip.has_value(), "test IPv4");
            expect(protocol::UdpView::parse(*ip).has_value() == parse_ok, "UDP rejection");
            expect(reply_for(*ip, LOCAL, PEER).has_value() == echo_ok, "Echo rejection");
        });
    };
    auto frame = request(5);
    frame[42] ^= 1;
    validate(frame, false, false);
    frame = request(5);
    frame[29] = 9;
    repair_ip(frame);
    validate(frame, false, false); // pseudo-header coverage
    frame = request(5);
    frame[23] = 6;
    repair_ip(frame);
    validate(frame, false, false);
    frame = request(5);
    write(frame, 38, 7);
    validate(frame, false, false);
    frame = request(5);
    write(frame, 38, 14);
    validate(frame, false, false); // underlying padding isn't IP payload
    frame = request(5);
    write(frame, 16, 27);
    repair_ip(frame);
    validate(frame, false, false);
    frame = request(5, false);
    frame[42] ^= 1;
    validate(frame, true, true); // IPv4 UDP checksum omitted
    frame = request(5);
    write(frame, 36, 19001);
    repair(frame);
    validate(frame, true, true);
    frame = request(5);
    write(frame, 34, 0);
    repair(frame);
    validate(frame, true, false); // legal UDP, no Echo return port
    frame = request(1473);
    validate(frame, true, false);
    frame = request(5);
    with_chain(frame, 39, [&](rte_mbuf const &packet, SplitFrame &) {
        auto ip = protocol::IPv4View::parse({&packet, 14, packet.pkt_len - 14});
        std::array<unsigned char, 6> invalid{};
        expect(not reply_for(*ip, LOCAL, invalid), "invalid peer MAC");
        invalid[0] = 1;
        expect(not reply_for(*ip, LOCAL, invalid), "multicast peer MAC");
    });
}
void check_zero_result() {
    auto frame = request(2, false);
    frame[42] = 0;
    frame[43] = 0;
    write(frame, 42, udp_reference(frame)); // makes computed checksum exactly zero
    expect(udp_reference(frame) == 0, "zero-checksum fixture");
    repair(frame);
    expect(read(frame, 40) == 0xffff, "fixture zero encoding");
    with_chain(frame, 43, [&](rte_mbuf const &packet, SplitFrame &) {
        auto ip = protocol::IPv4View::parse({&packet, 14, packet.pkt_len - 14});
        auto reply = reply_for(*ip, LOCAL, PEER);
        expect(reply and read(*reply, 40) == 0xffff and udp_reference(*reply) == 0,
               "computed zero must be encoded as ffff");
    });
}
} // namespace
void check_registry() {
    protocol::UdpPortRegistry ports;
    int echo_calls = 0, custom_calls = 0;
    bool should_send = true;
    Frame output;
    protocol::UdpFrameSender send = [&](protocol::Bytes<> bytes) {
        output.assign(bytes.begin(), bytes.end());
        return true;
    };
    auto throws = [](auto fn) {
        bool caught = false;
        try {
            fn();
        } catch (std::exception const &) {
            caught = true;
        }
        expect(caught, "registration error expected");
    };
    ports.register_port(19000, [&](auto const &datagram, auto const &reply) {
        ++echo_calls;
        expect(datagram.source.port == 40000 and datagram.destination.port == 19000,
               "callback endpoints");
        expect(reply.send(datagram.payload) == should_send, "slice reply status");
    });
    ports.register_port(19001, [&](auto const &datagram, auto const &reply) {
        ++custom_calls;
        expect(datagram.destination.port == 19001, "custom port");
        std::array<unsigned char, 2> body{'O', 'K'};
        expect(reply.send(protocol::Bytes<>{body}), "different-length reply");
        std::array<unsigned char, 1473> oversized{};
        expect(not reply.send(protocol::Bytes<>{oversized}), "reply MTU");
    });
    throws([&] { ports.register_port(19000, [](auto const &, auto const &) {}); });
    throws([&] { ports.register_port(0, [](auto const &, auto const &) {}); });
    throws([&] { ports.register_port(19002, {}); });
    auto dispatch = [&](Frame const &frame, protocol::UdpFrameSender const &sender) {
        protocol::UdpDispatchResult result{};
        with_chain(frame, 43, [&](rte_mbuf const &packet, SplitFrame &) {
            auto ip = protocol::IPv4View::parse({&packet, 14, packet.pkt_len - 14});
            expect(ip.has_value(), "registry IP");
            result = ports.dispatch(*ip, LOCAL, PEER, sender);
        });
        return result;
    };
    throws([&] { dispatch(request(5), send); });
    ports.freeze();
    throws([&] { ports.register_port(19002, [](auto const &, auto const &) {}); });
    expect(dispatch(request(5), send) == protocol::UdpDispatchResult::Handled, "echo dispatch");
    expect(echo_calls == 1 and output[42] == 0 and read(output, 36) == 40000, "echo callback");
    auto frame = request(5);
    write(frame, 36, 19001);
    repair(frame);
    expect(dispatch(frame, send) == protocol::UdpDispatchResult::Handled and custom_calls == 1,
           "custom dispatch");
    expect(read(output, 34) == 19001 and read(output, 16) == 30 and read(output, 38) == 10 and
               output[42] == 'O' and output[43] == 'K',
           "custom reply fields");
    expect(udp_reference(output) == 0 and reference(protocol::Bytes<>{output}.subspan(14, 20)) == 0,
           "custom checksums");
    frame = request(5);
    write(frame, 36, 19002);
    repair(frame);
    expect(dispatch(frame, send) == protocol::UdpDispatchResult::Unregistered, "unregistered port");
    frame = request(5);
    frame[42] ^= 1;
    expect(dispatch(frame, send) == protocol::UdpDispatchResult::Invalid,
           "invalid never dispatched");
    expect(echo_calls == 1 and custom_calls == 1, "unexpected callback count");
    protocol::UdpFrameSender rejected = [](auto) { return false; };
    should_send = false;
    expect(dispatch(request(5), rejected) == protocol::UdpDispatchResult::Handled, "TX rejected");
    protocol::UdpFrameSender throwing = [](auto) -> bool {
        throw std::runtime_error("callback TX");
    };
    throws([&] { dispatch(request(5), throwing); });
}

int main() {
    try {
        for (std::size_t size : {0, 1, 5, 56}) {
            auto frame = request(size);
            for (std::size_t cut = 0; cut <= frame.size(); ++cut)
                check_echo(size, cut);
        }
        for (std::size_t cut : {0, 33, 34, 39, 40, 41, 42, 43, 1514})
            check_echo(1472, cut);
        check_echo(5, 39, false);
        check_echo(5, 43, true, 9);
        check_registry();
        check_rejections();
        check_zero_result();
        std::puts("PASS: UDP splits, pseudo-header/checksum, bounds, zero checksum, Echo and MTU");
        return 0;
    } catch (std::exception const &error) {
        std::fprintf(stderr, "%s\n", error.what());
        return 1;
    }
}
