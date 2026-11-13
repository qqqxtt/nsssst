#pragma once
#include "checksum.hpp"
#include "tcp_manager.hpp"
#include <cstdio>
#include <source_location>
#include <stdexcept>
#include <string>
using namespace protocol;
inline void check(bool b, std::source_location where = std::source_location::current()) {
    if (not b)
        throw std::runtime_error("TCP test failed at line " + std::to_string(where.line()));
}
inline void put(std::span<unsigned char> b, unsigned off, std::uint32_t n, unsigned count) {
    for (unsigned i = 0; i < count; ++i)
        b[off + i] = static_cast<unsigned char>(n >> (8 * (count - i - 1)));
}
struct Input {
    std::vector<unsigned char> bytes;
    rte_mbuf head{}, tail{};
    Input(std::uint32_t seq, std::uint32_t ack, unsigned flags, std::string text = "", unsigned window = 32768)
        : bytes(40 + text.size()) {
        auto ip = std::span<unsigned char>{bytes}.first(20);
        ip[0] = 0x45;
        put(ip, 2, bytes.size(), 2);
        ip[8] = 64;
        ip[9] = 6;
        ip[12] = 192;
        ip[14] = 2;
        ip[15] = 1;
        ip[16] = 192;
        ip[18] = 2;
        ip[19] = 2;
        put(ip, 10, internet_checksum(ip), 2);
        auto tcp = std::span<unsigned char>{bytes}.subspan(20);
        put(tcp, 0, 12345, 2);
        put(tcp, 2, 19000, 2);
        put(tcp, 4, seq, 4);
        put(tcp, 8, ack, 4);
        tcp[12] = 0x50;
        tcp[13] = flags;
        put(tcp, 14, window, 2);
        std::copy(text.begin(), text.end(), tcp.begin() + 20);
        std::array<unsigned char, 12> pseudo{192, 0, 2, 1, 192, 0, 2, 2, 0, 6, 0, 0};
        put(pseudo, 10, tcp.size(), 2);
        InternetChecksum c;
        c.add(pseudo);
        c.add(tcp);
        put(tcp, 16, c.value(), 2);
        head.buf_addr = bytes.data();
        head.data_len = bytes.size() - 1;
        head.pkt_len = bytes.size();
        head.nb_segs = 2;
        head.next = &tail;
        tail.buf_addr = bytes.data() + bytes.size() - 1;
        tail.data_len = 1;
        tail.nb_segs = 1;
        // Original test owner remains alive: retained references must return to one.
        rte_mbuf_refcnt_set(&head, 1);
        rte_mbuf_refcnt_set(&tail, 1);
    }
    void deliver(TcpManager &m, TcpManager::Clock::time_point now, ReceiveTrace *trace = nullptr) {
        auto ip = IPv4View::parse({&head, 0, head.pkt_len});
        check(ip.has_value());
        auto tcp = TcpView::parse(*ip);
        check(tcp.has_value());
        m.receive(*ip, *tcp, MacAddress{2, 0, 0, 0, 0, 1}, now, trace);
    }
};
// Parses a frame the manager sent (Ethernet + IPv4 + TCP). The header is an owned snapshot, but
// the payload slice refers to a temporary mbuf: use only payload().length, never its bytes.
inline TcpView sent_segment(std::vector<unsigned char> &frame) {
    rte_mbuf p{};
    p.buf_addr = frame.data();
    p.data_len = static_cast<std::uint16_t>(frame.size());
    p.pkt_len = static_cast<std::uint32_t>(frame.size());
    p.nb_segs = 1;
    auto ip = IPv4View::parse({&p, 14, p.pkt_len - 14});
    check(ip.has_value());
    auto tcp = TcpView::parse(*ip);
    check(tcp.has_value());
    return *tcp;
}
