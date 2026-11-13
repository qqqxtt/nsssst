#pragma once

#include "address.hpp"
#include "receive_trace.hpp"
#include "arp_cache.hpp"
#include "mbuf_slice.hpp"
#include "tcp_manager.hpp"
#include <functional>
#include <vector>

namespace protocol {

class UdpPortRegistry;
class EthernetView;
class IPv4View;
// True means locally accepted (possibly queued); frame bytes are borrowed only during the call.
using FrameSender = std::function<bool(Bytes<>)>;
struct StackConfig {
    LocalAddress local;
    std::optional<Ipv4Address> gateway;
    unsigned prefix_length{24};
    bool quiet{};
};

// Single-threaded synchronous processing. Packet and callback views are borrowed.
// The UDP registry and objects captured by sender must outlive the stack.
class Stack {
  public:
    Stack(StackConfig config, UdpPortRegistry const &registry, FrameSender sender);
    Stack(Stack const &) = delete;
    Stack &operator=(Stack const &) = delete;
    Stack(Stack &&) = delete;
    Stack &operator=(Stack &&) = delete;

    void start();
    TcpManager &tcp() noexcept { return tcp_; }
    void poll(TcpManager::Clock::time_point now) { tcp_.poll(now); }
    void receive(rte_mbuf const &packet, ReceiveTrace *trace = nullptr) {
        receive(packet, TcpManager::Clock::now(), trace);
    }
    // `now` is shared by every packet of one RX burst, avoiding a clock read per packet.
    void receive(rte_mbuf const &packet, TcpManager::Clock::time_point now,
                 ReceiveTrace *trace = nullptr);
    // See TcpManager::begin_batch: coalesce data ACKs over one RX burst.
    void begin_batch() noexcept { tcp_.begin_batch(); }
    void end_batch() { tcp_.end_batch(); }
    // Idle cache warm-up: parses a prebuilt TCP frame through the Ethernet, IPv4 and TCP
    // views (checksum included). Touches no connection state. Returns parse success.
    bool warm() const;

  private:
    void handle_frame(rte_mbuf const &packet);
    void transmit(Bytes<> frame);
    void inspect_arp(EthernetView const &ethernet);
    void inspect_icmp(IPv4View const &ip, EthernetView const &ethernet);
    void inspect_udp(IPv4View const &ip, EthernetView const &ethernet);
    void inspect_ipv4(EthernetView const &ethernet);

    ReceiveTrace *trace_{};
    TcpManager::Clock::time_point now_{};
    StackConfig config_;
    UdpPortRegistry const &registry_;
    FrameSender sender_;
    ArpCache cache_;
    TcpManager tcp_;
    bool started_{};
    std::vector<unsigned char> warm_frame_;
    rte_mbuf warm_mbuf_{};
};

} // namespace protocol
