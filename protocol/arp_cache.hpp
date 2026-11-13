#pragma once

#include "address.hpp"
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <list>
#include <optional>
#include <unordered_map>

namespace protocol {

class ArpCache {
    // Address admissibility is checked by the protocol stack before learning.
  public:
    using Clock = std::chrono::steady_clock;

    explicit ArpCache(std::size_t capacity = 64, Clock::duration ttl = std::chrono::seconds{60});
    ArpCache(ArpCache const&) = delete;
    ArpCache& operator=(ArpCache const&) = delete;
    ArpCache(ArpCache&&) = delete;
    ArpCache& operator=(ArpCache&&) = delete;

    std::optional<MacAddress> lookup(Ipv4Address ip, Clock::time_point now);
    bool learn(Ipv4Address ip, MacAddress mac, Clock::time_point now, bool allow_insert = true);
    std::size_t size() const noexcept { return index_.size(); }

  private:
    struct Entry {
        Ipv4Address ip;
        MacAddress mac;
        Clock::time_point expires_at;
    };
    static std::uint32_t key(Ipv4Address ip) noexcept;
    void erase(std::list<Entry>::iterator entry);

    std::size_t capacity_;
    Clock::duration ttl_;
    std::list<Entry> lru_;
    std::unordered_map<std::uint32_t, std::list<Entry>::iterator> index_;
};

} // namespace protocol
