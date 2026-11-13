#pragma once
#include "arp.hpp"
#include "arp_cache.hpp"

namespace protocol {


using ArpFrame = std::array<unsigned char, 60>; // Ethernet frame, without FCS
ArpFrame build_arp_request(LocalAddress const& local, Ipv4Address target);
ArpFrame build_arp_reply(LocalAddress const& local, ARPView const& request);

} // namespace protocol
