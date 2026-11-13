#include "arp.hpp"
#include "ethernet.hpp"
#include "mbuf_chain.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <stdexcept>

namespace {
void expect(bool condition) {
    if (not condition) throw std::runtime_error("ARP test failed");
}

constexpr std::array<unsigned char, 28> REQUEST{
    0, 1, 8, 0, 6, 4, 0, 1,
    2, 0, 0, 0, 0, 1, 192, 0, 2, 1,
    0, 0, 0, 0, 0, 0, 192, 0, 2, 2
};

// Local descriptors backed by arrays; no EAL, mempool, device or sockets needed.
void check_split(std::size_t cut, unsigned char opcode) {
    std::array<unsigned char, 60> frame{};
    frame[12] = 8;
    frame[13] = 6;
    std::copy(REQUEST.begin(), REQUEST.end(), frame.begin() + 14);
    frame[21] = opcode;
    std::fill(frame.begin() + 42, frame.end(), 0xa5); // Ethernet padding

    SplitFrame chain{frame, cut};
    auto const &head = chain.packet();
    auto const result = protocol::EthernetView::parse(head);
    expect(result.has_value());
    expect(result->ether_type() == 0x0806);
    auto const arp = protocol::ARPView::parse(result->payload());
    expect(arp.has_value());
    expect(arp->hardware_type() == 1 and arp->protocol_type() == 0x0800);
    expect(arp->hardware_length() == 6 and arp->protocol_length() == 4);
    expect(arp->operation() == static_cast<protocol::ArpOperation>(opcode));
    auto same = [](auto actual, std::size_t offset) {
        return std::equal(actual.begin(), actual.end(), REQUEST.begin() + offset);
    };
    expect(same(arp->sender_hardware_address(), 8));
    expect(same(arp->sender_protocol_address(), 14));
    expect(same(arp->target_hardware_address(), 18));
    expect(same(arp->target_protocol_address(), 24));

    std::size_t seen = 0;
    expect(protocol::for_each_chunk(result->payload(), [&](auto bytes) {
        expect(not bytes.empty());
        expect(bytes.data() == chain.address(14 + seen));
        seen += bytes.size();
    }));
    expect(seen == 46);
    for (std::uint32_t length = 0; length < 28; ++length) {
        expect(not protocol::ARPView::parse({&head, 14, length}));
    }
    expect(protocol::ARPView::parse({&head, 14, 28}).has_value());
    expect(not protocol::ARPView::parse({}));
    expect(not protocol::ARPView::parse({&head, 61, 28}));
    expect(not protocol::ARPView::parse({&head, 14, 47}));
    expect(not protocol::ARPView::parse({&head, 0xffffffffU, 28}));

    for (auto field : {0U, 1U, 2U, 3U, 4U, 5U, 6U, 7U}) {
        auto &byte = chain.at(14 + field);
        auto const saved = byte;
        byte = 0xff;
        expect(not protocol::ARPView::parse(result->payload()));
        byte = saved;
    }
    chain.clear();
    expect(same(arp->sender_hardware_address(), 8)); // owns snapshot
    expect(same(arp->target_protocol_address(), 24));
}
}

int main() {
    try {
        for (std::size_t cut = 0; cut <= 60; ++cut) {
            check_split(cut, 1);
            check_split(cut, 2);
        }
        std::puts("PASS: ARP request/reply, all 61 cuts, empty segments, bounds and snapshots");
        return 0;
    } catch (std::exception const &error) {
        std::fprintf(stderr, "%s\n", error.what());
        return 1;
    }
}
