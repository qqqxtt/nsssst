#include "arp_cache.hpp"

#include <algorithm>
#include <iterator>
#include <stdexcept>

namespace protocol {

ArpCache::ArpCache(std::size_t capacity, Clock::duration ttl)
    : capacity_(capacity),
      ttl_(ttl) {
    if (capacity == 0 or ttl <= Clock::duration::zero())
        throw std::invalid_argument("invalid ARP cache capacity/TTL");
    index_.reserve(capacity);
}

std::uint32_t ArpCache::key(Ipv4Address ip) noexcept {
    return (std::uint32_t{ip[0]} << 24) | (std::uint32_t{ip[1]} << 16) |
           (std::uint32_t{ip[2]} << 8) | ip[3];
}

void ArpCache::erase(std::list<Entry>::iterator entry) {
    index_.erase(key(entry->ip));
    lru_.erase(entry);
}

std::optional<MacAddress> ArpCache::lookup(Ipv4Address ip, Clock::time_point now) {
    auto found = index_.find(key(ip));
    if (found == index_.end())
        return std::nullopt;

    auto entry = found->second;
    if (now >= entry->expires_at) {
        erase(entry);
        return std::nullopt;
    }
    lru_.splice(lru_.begin(), lru_, entry);

    return entry->mac;
}

bool ArpCache::learn(Ipv4Address ip, MacAddress mac, Clock::time_point now, bool allow_insert) {
    auto found = index_.find(key(ip));
    if (found != index_.end()) {
        auto entry = found->second;
        if (now < entry->expires_at or allow_insert) {
            entry->mac = mac;
            entry->expires_at = now + ttl_;
            lru_.splice(lru_.begin(), lru_, entry);
            return true;
        }
        erase(entry);
    }

    if (not allow_insert)
        return false;

    if (index_.size() >= capacity_) {
        for (auto it = lru_.begin(); it != lru_.end();) {
            auto current = it++;
            if (now >= current->expires_at)
                erase(current);
        }
    }

    lru_.push_front({ip, mac, now + ttl_});
    try {
        index_.emplace(key(ip), lru_.begin());
    } catch (...) {
        lru_.pop_front();
        throw;
    }
    if (index_.size() > capacity_)
        erase(std::prev(lru_.end()));
    return true;
}
} // namespace protocol
