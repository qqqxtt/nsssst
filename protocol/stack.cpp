#include "stack.hpp"
#include "arp_sender.hpp"
#include "ethernet.hpp"
#include "icmp.hpp"
#include "ipv4.hpp"
#include "tcp.hpp"
#include "udp_registry.hpp"
#include "checksum.hpp"
#include <algorithm>
#include <cstdio>
#include <stdexcept>
#include <utility>

namespace protocol {
namespace {
void print_mac(protocol::Bytes<6> address) {
    std::printf("%02x:%02x:%02x:%02x:%02x:%02x", static_cast<unsigned>(address[0]),
                static_cast<unsigned>(address[1]), static_cast<unsigned>(address[2]),
                static_cast<unsigned>(address[3]), static_cast<unsigned>(address[4]),
                static_cast<unsigned>(address[5]));
}

void print_ip(protocol::Bytes<4> address) {
    std::printf("%u.%u.%u.%u", static_cast<unsigned>(address[0]), static_cast<unsigned>(address[1]),
                static_cast<unsigned>(address[2]), static_cast<unsigned>(address[3]));
}

} // namespace

Stack::Stack(StackConfig config, UdpPortRegistry const &registry, FrameSender sender)
    : config_(config), registry_(registry), sender_(std::move(sender)),
      tcp_(config.local, sender_, [this](Ipv4Address ip, TcpManager::Clock::time_point now) {
          if (config_.gateway) {
              unsigned bits = config_.prefix_length;
              bool local = true;
              for (unsigned i = 0; i < 4; ++i) {
                  unsigned n = std::min(bits, 8U);
                  unsigned mask = n ? (255U << (8 - n)) & 255 : 0;
                  if ((ip[i] & mask) != (config_.local.ip[i] & mask))
                      local = false;
                  bits -= n;
              }
              if (not local)
                  ip = *config_.gateway;
          }
          auto mac = cache_.lookup(ip, now);
          if (not mac)
              transmit(build_arp_request(config_.local, ip));
          return mac;
      }) {
    if (config_.prefix_length > 32 or (config_.gateway and not valid_peer_ip(*config_.gateway)))
        throw std::invalid_argument("invalid gateway/prefix");
    if (not sender_ or not valid_peer_ip(config_.local.ip) or not valid_peer_mac(config_.local.mac))
        throw std::invalid_argument("invalid stack configuration");
    // Warm-up frame: a 128-byte TCP segment from 198.51.100.1:443 to this host.
    constexpr std::size_t payload = 128;
    warm_frame_.assign(54 + payload, 0x5a);
    auto &f = warm_frame_;
    std::copy(config_.local.mac.begin(), config_.local.mac.end(), f.begin());
    MacAddress const peer_mac{2, 0, 0, 0, 0, 0x77};
    std::copy(peer_mac.begin(), peer_mac.end(), f.begin() + 6);
    f[12] = 0x08, f[13] = 0x00;
    std::fill(f.begin() + 14, f.begin() + 54, 0);
    f[14] = 0x45;
    auto ip_length = 20 + 20 + payload;
    f[16] = static_cast<unsigned char>(ip_length >> 8), f[17] = static_cast<unsigned char>(ip_length);
    f[22] = 64, f[23] = IP_PROTOCOL_TCP;
    Ipv4Address const peer_ip{198, 51, 100, 1};
    std::copy(peer_ip.begin(), peer_ip.end(), f.begin() + 26);
    std::copy(config_.local.ip.begin(), config_.local.ip.end(), f.begin() + 30);
    auto ip_sum = internet_checksum(Bytes<>{f}.subspan(14, 20));
    f[24] = static_cast<unsigned char>(ip_sum >> 8), f[25] = static_cast<unsigned char>(ip_sum);
    f[34] = 0x01, f[35] = 0xbb, f[36] = 0x9c, f[37] = 0x40; // 443 -> 40000
    f[46] = 0x50, f[47] = 0x18;                              // header 20 bytes, PSH|ACK
    f[48] = 0x80;                                            // window 32768
    std::array<unsigned char, 12> pseudo{};
    std::copy(peer_ip.begin(), peer_ip.end(), pseudo.begin());
    std::copy(config_.local.ip.begin(), config_.local.ip.end(), pseudo.begin() + 4);
    pseudo[9] = IP_PROTOCOL_TCP;
    pseudo[10] = static_cast<unsigned char>((20 + payload) >> 8);
    pseudo[11] = static_cast<unsigned char>(20 + payload);
    InternetChecksum tcp_sum;
    tcp_sum.add(pseudo);
    tcp_sum.add(Bytes<>{f}.subspan(34));
    auto sum = tcp_sum.value();
    f[50] = static_cast<unsigned char>(sum >> 8), f[51] = static_cast<unsigned char>(sum);
    warm_mbuf_.buf_addr = f.data();
    warm_mbuf_.data_off = 0;
    warm_mbuf_.data_len = static_cast<std::uint16_t>(f.size());
    warm_mbuf_.pkt_len = static_cast<std::uint32_t>(f.size());
    warm_mbuf_.nb_segs = 1;
}

bool Stack::warm() const {
    auto ethernet = EthernetView::parse(warm_mbuf_);
    if (not ethernet or not std::equal(ethernet->destination().begin(),
                                       ethernet->destination().end(), config_.local.mac.begin()))
        return false;
    auto ip = IPv4View::parse(ethernet->payload());
    if (not ip)
        return false;
    auto tcp = TcpView::parse(*ip);
    return tcp and tcp->payload().length == 128;
}

void Stack::start() {
    if (started_)
        throw std::logic_error("stack already started");
    started_ = true;
    std::printf("Local ARP address: ");
    print_ip(config_.local.ip);
    std::printf(" / ");
    print_mac(config_.local.mac);
    std::puts("");
}

void Stack::receive(rte_mbuf const &packet, TcpManager::Clock::time_point now,
                    ReceiveTrace *trace) {
    ReceiveTraceScope scope{trace_, trace};
    now_ = now;
    if (not started_)
        throw std::logic_error("start stack before receive");
    handle_frame(packet);
}

void Stack::handle_frame(rte_mbuf const &packet) {
    auto ethernet = EthernetView::parse(packet);
    if (not ethernet) {
        std::fputs("Truncated Ethernet header\n", stderr);
        return;
    }

    auto dst = ethernet->destination();
    bool broadcast = std::all_of(dst.begin(), dst.end(), [](auto b) { return b == 255; });
    if (not broadcast and not std::equal(dst.begin(), dst.end(), config_.local.mac.begin()))
        return;

    switch (ethernet->ether_type()) {
    case 0x0806:
        inspect_arp(*ethernet);
        break;
    case 0x0800:
        inspect_ipv4(*ethernet);
        break;
    default:
        break;
    }
}
void Stack::transmit(Bytes<> frame) {
    if (not sender_(frame))
        std::fputs("ARP TX dropped: allocation failure or queue busy\n", stderr);
}

void Stack::inspect_arp(protocol::EthernetView const &ethernet) {
    auto const arp = protocol::ARPView::parse(ethernet.payload());
    if (not arp) {
        std::fputs("Invalid or unsupported ARP packet\n", stderr);
        return;
    }

    if (not std::equal(ethernet.source().begin(), ethernet.source().end(),
                       arp->sender_hardware_address().begin()))
        return;

    protocol::MacAddress sender_mac{};
    protocol::Ipv4Address sender_ip{};
    std::copy(arp->sender_hardware_address().begin(), arp->sender_hardware_address().end(),
              sender_mac.begin());
    std::copy(arp->sender_protocol_address().begin(), arp->sender_protocol_address().end(),
              sender_ip.begin());
    if (not protocol::valid_peer_mac(sender_mac))
        return;

    if (sender_ip == config_.local.ip) {
        if (sender_mac != config_.local.mac)
            std::fputs("ARP local IPv4 address conflict\n", stderr);
        return;
    }

    bool const for_us = std::equal(config_.local.ip.begin(), config_.local.ip.end(),
                                   arp->target_protocol_address().begin());
    if (valid_peer_ip(sender_ip) and
        cache_.learn(sender_ip, sender_mac, protocol::ArpCache::Clock::now(), for_us) and
        not config_.quiet) {
        std::printf("ARP cache learned ");
        print_ip(sender_ip);
        std::printf(" -> ");
        print_mac(sender_mac);
        std::puts("");
    }
    if (for_us and arp->operation() == protocol::ArpOperation::Request)
        transmit(protocol::build_arp_reply(config_.local, *arp));

    if (not config_.quiet) {
        std::printf("ARP %s: sender=",
                    arp->operation() == protocol::ArpOperation::Request ? "request" : "reply");
        print_ip(arp->sender_protocol_address());
        std::printf(" (");
        print_mac(arp->sender_hardware_address());
        std::printf(") target=");
        print_ip(arp->target_protocol_address());
        std::printf(" (");
        print_mac(arp->target_hardware_address());
        std::puts(")");
    }
}

void Stack::inspect_icmp(protocol::IPv4View const &ip, protocol::EthernetView const &ethernet) {
    // Echo service is unicast only, including the Ethernet destination.
    if (not std::equal(ethernet.destination().begin(), ethernet.destination().end(),
                       config_.local.mac.begin()))
        return;
    auto const echo = protocol::ICMPEchoView::parse(ip.payload());
    if (not echo) {
        std::fputs("Invalid or unsupported ICMP packet\n", stderr);
        return;
    }
    if (not config_.quiet) {
        std::printf("ICMP echo %s id=%u seq=%u data=%u bytes\n",
                    echo->type() == protocol::IcmpEchoType::Request ? "request" : "reply",
                    static_cast<unsigned>(echo->identifier()), static_cast<unsigned>(echo->sequence()),
                    static_cast<unsigned>(echo->payload().length));
    }
    if (echo->type() == protocol::IcmpEchoType::Reply)
        return;
    auto reply = protocol::build_icmp_echo_reply(ip, config_.local.mac, ethernet.source());
    if (not reply) {
        std::fputs("ICMP echo request unsupported or exceeds 1500-byte MTU\n", stderr);
        return;
    }
    if (not sender_(*reply))
        std::fputs("ICMP TX dropped: allocation failure or queue busy\n", stderr);
}

void Stack::inspect_udp(protocol::IPv4View const &ip, protocol::EthernetView const &ethernet) {
    if (not std::equal(ethernet.destination().begin(), ethernet.destination().end(),
                       config_.local.mac.begin()))
        return;
    auto result = registry_.dispatch(ip, config_.local.mac, ethernet.source(), sender_, trace_);
    if (result == protocol::UdpDispatchResult::Invalid)
        std::fputs("Invalid UDP length or checksum\n", stderr);
}

void Stack::inspect_ipv4(protocol::EthernetView const &ethernet) {
    auto const ip = protocol::IPv4View::parse(ethernet.payload());
    if (not ip) {
        std::fputs("Invalid or unsupported IPv4 packet\n", stderr);
        return;
    }
    if (not std::equal(ip->destination().begin(), ip->destination().end(),
                       config_.local.ip.begin()))
        return;

    if (not config_.quiet) {
        std::printf("IPv4 ");
        print_ip(ip->source());
        std::printf(" -> ");
        print_ip(ip->destination());
        std::printf(" protocol=%u ttl=%u total=%u payload=%u bytes\n",
                    static_cast<unsigned>(ip->protocol()), static_cast<unsigned>(ip->ttl()),
                    static_cast<unsigned>(ip->total_length()),
                    static_cast<unsigned>(ip->payload().length));
    }
    if (trace_) trace_->transport = ip->protocol();
    if (ip->protocol() == protocol::IP_PROTOCOL_ICMP) {
        inspect_icmp(*ip, ethernet);
        return;
    }
    if (ip->protocol() == IP_PROTOCOL_TCP) {
        auto tcp = TcpView::parse(*ip);
        if (not tcp) {
            std::fputs("Invalid TCP header, options or checksum\n", stderr);
            return;
        }
        if (std::equal(ethernet.destination().begin(), ethernet.destination().end(),
                       config_.local.mac.begin()))
            tcp_.receive(*ip, *tcp, ethernet.source(), now_, trace_);
        return;
    }
    if (ip->protocol() == protocol::IP_PROTOCOL_UDP) {
        inspect_udp(*ip, ethernet);
        return;
    }
    if (config_.quiet)
        return;
    if (not protocol::for_each_chunk(ip->payload(), [](protocol::Bytes<> chunk) {
            std::printf("  contiguous chunk: %zu bytes\n", chunk.size());
        })) {
        std::fputs("Invalid IPv4 payload range\n", stderr);
    }
}

} // namespace protocol
