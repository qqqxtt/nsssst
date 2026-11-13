#include "udp_registry.hpp"
#include <stdexcept>
#include <utility>
namespace protocol {
bool UdpReplySender::send(Bytes<> payload) const {
    auto frame = build_udp_reply(info_, payload);
    return frame and sender_(*frame);
}
bool UdpReplySender::send(PacketSlice const &payload) const {
    auto frame = build_udp_reply(info_, payload);
    return frame and sender_(*frame);
}
void UdpPortRegistry::register_port(std::uint16_t port, UdpHandler handler) {
    if (frozen_)
        throw std::logic_error("UDP registry is frozen");
    if (port == 0 or not handler)
        throw std::invalid_argument("invalid UDP registration");
    if (not handlers_.emplace(port, std::move(handler)).second)
        throw std::invalid_argument("UDP port already registered");
}
UdpDispatchResult UdpPortRegistry::dispatch(IPv4View const &ip, Bytes<6> local_mac,
                                            Bytes<6> peer_mac, UdpFrameSender const &sender, ReceiveTrace *trace) const {
    if (not frozen_)
        throw std::logic_error("freeze UDP registry before dispatch");
    if (not sender)
        throw std::invalid_argument("empty UDP frame sender");
    auto udp = UdpView::parse(ip);
    if (not udp)
        return UdpDispatchResult::Invalid;
    auto found = handlers_.find(udp->destination_port());
    if (found == handlers_.end())
        return UdpDispatchResult::Unregistered;
    UdpDatagramView datagram{};
    std::copy(ip.source().begin(), ip.source().end(), datagram.source.address.begin());
    std::copy(ip.destination().begin(), ip.destination().end(),
              datagram.destination.address.begin());
    datagram.source.port = udp->source_port();
    datagram.destination.port = udp->destination_port();
    datagram.payload = udp->payload();
    UdpReplyInfo info{datagram.destination, datagram.source, {}, {}};
    std::copy(local_mac.begin(), local_mac.end(), info.local_mac.begin());
    std::copy(peer_mac.begin(), peer_mac.end(), info.peer_mac.begin());
    UdpReplySender reply{info, sender};
    trace_delivery(trace);
    found->second(datagram, reply);
    return UdpDispatchResult::Handled;
}
} // namespace protocol
