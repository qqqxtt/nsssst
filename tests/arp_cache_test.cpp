#include "arp_sender.hpp"
#include <cstdio>
#include <stdexcept>

void check(bool ok) {
    if (not ok)
        throw std::runtime_error("ARP cache/sender test failed");
}
int main() {
    using namespace protocol;
    auto now = ArpCache::Clock::time_point{};
    auto seconds = [](int n) { return std::chrono::seconds{n}; };
    Ipv4Address a{192, 0, 2, 1}, b{192, 0, 2, 2}, c{192, 0, 2, 3};
    MacAddress mac{2, 0, 0, 0, 0, 1}, other{2, 0, 0, 0, 0, 2};
    ArpCache cache{2, seconds(10)};
    check(cache.learn(a, mac, now));
    check(cache.learn(b, mac, now));
    check(cache.lookup(a, now + seconds(1)) == mac);
    check(cache.learn(c, other, now + seconds(2)));
    check(not cache.lookup(b, now + seconds(2))); // LRU victim
    check(cache.lookup(a, now + seconds(9)) == mac);
    check(not cache.lookup(a, now + seconds(10))); // reads did not extend TTL
    check(not cache.learn(b, mac, now, false));
    check(cache.learn(c, mac, now + seconds(3), false));
    check(cache.lookup(c, now + seconds(12)) == mac);
    check(not cache.lookup(c, now + seconds(13)));
    check(not valid_peer_ip({}));
    check(not valid_peer_mac({}));
    ArpCache pressure{2, seconds(10)};
    check(pressure.learn(a, mac, now));
    check(pressure.learn(b, mac, now + seconds(5)));
    check(pressure.lookup(a, now + seconds(9)).has_value());
    check(pressure.learn(c, mac, now + seconds(11)));
    check(pressure.lookup(b, now + seconds(11)).has_value()); // expired MRU reclaimed
    LocalAddress local{other, b};
    auto request = build_arp_request(local, a);
    rte_mbuf packet{};
    packet.buf_addr = request.data();
    packet.data_len = 60;
    packet.pkt_len = 60;
    packet.nb_segs = 1;
    auto parsed = ARPView::parse({&packet, 14, 46});
    check(parsed and parsed->operation() == ArpOperation::Request);
    check(request[0] == 255 and request[21] == 1 and request[32] == 0);
    auto reply = build_arp_reply({mac, a}, *parsed);
    packet.buf_addr = reply.data();
    auto response = ARPView::parse({&packet, 14, 46});
    check(response and response->operation() == ArpOperation::Reply);
    check(std::equal(response->sender_protocol_address().begin(),
                     response->sender_protocol_address().end(), a.begin()));
    check(std::equal(response->target_hardware_address().begin(),
                     response->target_hardware_address().end(), other.begin()));
    check(std::all_of(reply.begin() + 42, reply.end(), [](auto v) { return v == 0; }));
    std::puts("PASS: LRU, lazy expiration, refresh, address validation, request/reply bytes");
}
