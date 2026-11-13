#include "arp_sender.hpp"
#include <stdexcept>

namespace protocol {
namespace {
ArpFrame build(LocalAddress const& local, MacAddress destination, MacAddress target_mac,
    Ipv4Address target_ip, unsigned char operation) {
    ArpFrame frame{};
    std::copy(destination.begin(), destination.end(), frame.begin());
    std::copy(local.mac.begin(), local.mac.end(), frame.begin() + 6);
    frame[12] = 8;
    frame[13] = 6;
    frame[15] = 1;
    frame[16] = 8;
    frame[18] = 6;
    frame[19] = 4;
    frame[21] = operation;
    std::copy(local.mac.begin(), local.mac.end(), frame.begin() + 22);
    std::copy(local.ip.begin(), local.ip.end(), frame.begin() + 28);
    std::copy(target_mac.begin(), target_mac.end(), frame.begin() + 32);
    std::copy(target_ip.begin(), target_ip.end(), frame.begin() + 38);
    return frame;
}
} // namespace

ArpFrame build_arp_request(LocalAddress const& local, Ipv4Address target) {
    return build(local, {255, 255, 255, 255, 255, 255}, {}, target, 1);
}

ArpFrame build_arp_reply(LocalAddress const& local, ARPView const& request) {
    if (request.operation() != ArpOperation::Request or
        not std::equal(local.ip.begin(), local.ip.end(), request.target_protocol_address().begin()))
        throw std::invalid_argument("ARP request is not for local IP");
    MacAddress target{};
    Ipv4Address ip{};
    std::copy(request.sender_hardware_address().begin(), request.sender_hardware_address().end(),
        target.begin());
    std::copy(request.sender_protocol_address().begin(), request.sender_protocol_address().end(),
        ip.begin());
    if (not valid_peer_mac(target))
        throw std::invalid_argument("invalid ARP sender MAC");
    return build(local, target, target, ip, 2);
}
} // namespace protocol
