#include "tcp.hpp"
#include <algorithm>
#include <cstdio>
#include <stdexcept>
#include <vector>

namespace {
using Buffer = std::vector<unsigned char>;
void check(bool value) {
    if (not value)
        throw std::runtime_error("TCP header test failed");
}
void put16(Buffer &b, std::size_t i, unsigned value) {
    b[i] = static_cast<unsigned char>(value >> 8);
    b[i + 1] = static_cast<unsigned char>(value);
}
// Independent checksum implementation: collect words, then fold carries.
unsigned checksum(Buffer const &b) {
    unsigned sum{};
    for (std::size_t i = 0; i < b.size(); i += 2)
        sum += (unsigned(b[i]) << 8) + (i + 1 < b.size() ? b[i + 1] : 0);
    while (sum >> 16)
        sum = (sum & 65535) + (sum >> 16);
    return (~sum) & 65535;
}
void seal(Buffer &b) {
    put16(b, 10, 0);
    put16(b, 10, checksum(Buffer(b.begin(), b.begin() + 20)));
    put16(b, 36, 0);
    Buffer pseudo(b.begin() + 12, b.begin() + 20);
    pseudo.insert(pseudo.end(), {0, 6, 0, 0});
    put16(pseudo, 10, b.size() - 20);
    pseudo.insert(pseudo.end(), b.begin() + 20, b.end());
    put16(b, 36, checksum(pseudo));
}
Buffer make(unsigned header_length, unsigned payload_length) {
    Buffer b(20 + header_length + payload_length);
    b[0] = 0x45;
    put16(b, 2, b.size());
    b[8] = 64;
    b[9] = 6;
    b[12] = 192;
    b[14] = 2;
    b[15] = 1;
    b[16] = 192;
    b[18] = 2;
    b[19] = 2;
    put16(b, 20, 12345);
    put16(b, 22, 19000);
    b[24] = 0x89;
    b[25] = 0xab;
    b[26] = 0xcd;
    b[27] = 0xef;
    b[28] = 0xfe;
    b[29] = 0xdc;
    b[30] = 0xba;
    b[31] = 0x98;
    b[32] = static_cast<unsigned char>((header_length / 4) << 4);
    b[33] = 0x12;
    put16(b, 34, 32768);
    put16(b, 38, 123);
    if (header_length > 20)
        std::fill(b.begin() + 40, b.begin() + 20 + header_length, 1);
    for (unsigned i = 0; i < payload_length; ++i)
        b[20 + header_length + i] = i + 1;
    seal(b);
    return b;
}
std::optional<protocol::TcpView> parse(Buffer &b) {
    rte_mbuf packet{};
    packet.buf_addr = b.data();
    packet.data_len = b.size();
    packet.pkt_len = b.size();
    packet.nb_segs = 1;
    auto ip = protocol::IPv4View::parse({&packet, 0, packet.pkt_len});
    check(ip.has_value());
    // Tests using this helper only inspect owned header data, never the borrowed payload.
    return protocol::TcpView::parse(*ip);
}
void split_tests() {
    for (unsigned h : {20U, 24U, 60U})
        for (unsigned n : {0U, 1U, 9U}) {
            auto b = make(h, n);
            for (std::size_t cut = 0; cut <= b.size(); ++cut) {
                Buffer first(cut + 3), last(b.size() - cut + 5);
                std::copy_n(b.begin(), cut, first.begin() + 3);
                std::copy(b.begin() + cut, b.end(), last.begin() + 5);
                rte_mbuf head{}, empty{}, tail{};
                head.buf_addr = first.data();
                head.data_off = 3;
                head.data_len = cut;
                head.pkt_len = b.size();
                head.nb_segs = 3;
                head.next = &empty;
                empty.buf_addr = first.data();
                empty.next = &tail;
                tail.buf_addr = last.data();
                tail.data_off = 5;
                tail.data_len = b.size() - cut;
                auto ip = protocol::IPv4View::parse({&head, 0, head.pkt_len});
                check(ip.has_value());
                auto tcp = protocol::TcpView::parse(*ip);
                check(tcp.has_value());
                check(tcp->source_port() == 12345 and tcp->destination_port() == 19000);
                check(tcp->sequence_number() == 0x89abcdef and
                      tcp->acknowledgment_number() == 0xfedcba98);
                check(tcp->header_length() == h and tcp->window() == 32768 and
                      tcp->urgent_pointer() == 123);
                check(tcp->has_flag(protocol::TcpFlag::Syn) and
                      tcp->has_flag(protocol::TcpFlag::Ack));
                check(not tcp->has_flag(protocol::TcpFlag::Fin));
                check(tcp->options().size() == h - 20);
                auto payload = tcp->payload();
                check(payload.packet == &head and payload.offset == 20 + h and payload.length == n);
                std::size_t seen{};
                check(protocol::for_each_chunk(payload, [&](auto chunk) {
                    auto offset = payload.offset + seen;
                    auto expected =
                        offset < cut ? first.data() + 3 + offset : last.data() + 5 + offset - cut;
                    check(chunk.data() == expected);
                    check(std::equal(chunk.begin(), chunk.end(), b.begin() + offset));
                    seen += chunk.size();
                }));
                check(seen == n);
                first.assign(first.size(), 0);
                last.assign(last.size(), 0);
                check(tcp->sequence_number() == 0x89abcdef);
                check(std::all_of(tcp->options().begin(), tcp->options().end(),
                                  [](auto x) { return x == 1; }));
            }
        }
}
void reject_tests() {
    auto b = make(20, 9);
    for (unsigned length = 0; length < 20; ++length) {
        auto short_b = b;
        short_b.resize(20 + length);
        put16(short_b, 2, short_b.size());
        put16(short_b, 10, 0);
        put16(short_b, 10, checksum(Buffer(short_b.begin(), short_b.begin() + 20)));
        check(not parse(short_b));
    }
    for (unsigned offset : {0U, 4U, 15U}) {
        b = make(20, 0);
        b[32] = offset << 4;
        seal(b);
        check(not parse(b));
    }
    b = make(20, 9);
    b.back() ^= 1;
    check(not parse(b));
    b = make(20, 0);
    b[15] ^= 1;
    put16(b, 10, 0);
    put16(b, 10, checksum(Buffer(b.begin(), b.begin() + 20)));
    check(not parse(b));
    b = make(20, 0);
    put16(b, 36, 0);
    check(not parse(b));
    b = make(20, 0);
    b[9] = 17;
    seal(b);
    check(not parse(b));
    // Known options, unknown TLV, NOP and EOL; reject malformed lengths.
    for (Buffer opt : {Buffer{2, 4, 5, 180}, Buffer{3, 3, 7, 1}, Buffer{4, 2, 1, 1},
                       Buffer{30, 4, 9, 8}, Buffer{0, 255, 255, 255}}) {
        b = make(24, 0);
        std::copy(opt.begin(), opt.end(), b.begin() + 40);
        seal(b);
        check(parse(b).has_value());
    }
    for (Buffer opt : {Buffer{2, 3, 5, 1}, Buffer{30, 0, 0, 0}, Buffer{30, 1, 0, 0},
                       Buffer{30, 5, 0, 0}, Buffer{1, 1, 1, 30}, Buffer{8, 4, 0, 0}}) {
        b = make(24, 0);
        std::copy(opt.begin(), opt.end(), b.begin() + 40);
        seal(b);
        check(not parse(b));
    }
    // Trailing bytes outside IPv4 Total Length do not enter TCP checksum or payload.
    b = make(20, 1);
    b.insert(b.end(), 16, 0xee);
    check(parse(b).has_value());
}
} // namespace
int main() {
    split_tests();
    reject_tests();
    std::puts("PASS: TCP fields, options, all mbuf cuts, snapshots, checksums and bounds");
}
