#include "arp_sender.hpp"
#include "stack.hpp"
#include "udp_registry.hpp"
#include <algorithm>
#include <cstdio>
#include <stdexcept>
#include <vector>

void check(bool ok) {
    if (not ok)
        throw std::runtime_error("stack test failed");
}
template <class Fn> void throws(Fn fn) {
    bool caught = false;
    try {
        fn();
    } catch (std::exception const &) {
        caught = true;
    }
    check(caught);
}
int main() {
    using namespace protocol;
    LocalAddress local{{2, 0, 0, 0, 0, 2}, {192, 0, 2, 2}},
        peer{{2, 0, 0, 0, 0, 1}, {192, 0, 2, 1}};
    UdpPortRegistry ports;
    ports.freeze();
    std::vector<std::vector<unsigned char>> sent;
    FrameSender sender = [&](Bytes<> bytes) {
        sent.emplace_back(bytes.begin(), bytes.end());
        return true;
    };
    Stack stack{{local}, ports, sender};
    auto frame = build_arp_request(peer, local.ip);
    auto receive = [&] {
        rte_mbuf packet{};
        packet.buf_addr = frame.data();
        packet.buf_len = frame.size();
        packet.pkt_len = frame.size();
        packet.data_len = frame.size();
        packet.nb_segs = 1;
        stack.receive(packet);
    };
    throws(receive);
    stack.start();
    if (not stack.warm()) throw std::runtime_error("warm-up frame must parse");
    if (not sent.empty()) throw std::runtime_error("warm-up must not transmit");
    check(sent.empty());
    throws([&] { stack.start(); });
    receive();
    check(sent.size() == 1 and sent[0][21] == 2 and sent[0][41] == 1);
    check(std::equal(peer.mac.begin(), peer.mac.end(), sent[0].begin()));
    // Probe is answered, despite its unspecified sender IP.
    std::fill(frame.begin() + 28, frame.begin() + 32, 0);
    receive();
    check(sent.size() == 2 and sent[1][41] == 0);
    // Ethernet source must agree with ARP SHA.
    frame = build_arp_request(peer, local.ip);
    frame[6] ^= 2;
    receive();
    check(sent.size() == 2);
    // Request for another IP and a conflicting local-IP claim produce no reply.
    frame = build_arp_request(peer, {192, 0, 2, 99});
    receive();
    check(sent.size() == 2);
    frame = build_arp_request(peer, local.ip);
    frame[31] = 2;
    receive();
    check(sent.size() == 2);
    // Active connect resolves through this stack's ARP cache before sending SYN.
    auto now = TcpManager::Clock::now();
    auto connecting = stack.tcp().connect({{192, 0, 2, 9}, 40000, 19000, {}},
                                          {.on_data = [](auto, PacketSlice) {}}, now);
    check(connecting != 0 and sent.back()[13] == 6 and sent.back()[41] == 9);
    LocalAddress remote{{2, 0, 0, 0, 0, 9}, {192, 0, 2, 9}};
    auto request_frame = build_arp_request(local, remote.ip);
    rte_mbuf request_packet{};
    request_packet.buf_addr = request_frame.data();
    request_packet.pkt_len = request_frame.size();
    request_packet.data_len = request_frame.size();
    request_packet.nb_segs = 1;
    auto request = ARPView::parse({&request_packet, 14, 46});
    check(request.has_value());
    frame = build_arp_reply(remote, *request);
    receive();
    stack.poll(now + std::chrono::seconds(1));
    check(sent.back()[13] == 0 and sent.back()[23] == 6 and sent.back()[47] == 2);
    throws([&] { Stack invalid{{local}, ports, {}}; });
    Stack routed{{local, peer.ip, 24}, ports, sender};
    routed.start();
    (void)routed.tcp().connect({{203, 0, 113, 10}, 40001, 443, {}},
                               {.on_data = [](auto, PacketSlice) {}}, now);
    check(sent.back()[13] == 6 and sent.back()[41] == 1); // ARP gateway, not remote .10.
    throws([&] { Stack invalid{{local, peer.ip, 33}, ports, sender}; });
    std::puts("PASS: stack lifecycle, ARP request/reply/probe, MAC consistency and filtering");
}
