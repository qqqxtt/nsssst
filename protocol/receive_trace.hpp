#pragma once
#include <cstdint>
#include <stdexcept>
#include <time.h>
namespace protocol {
inline std::uint64_t receive_clock_ns() {
    timespec ts{};
    if (clock_gettime(CLOCK_MONOTONIC, &ts))
        throw std::runtime_error("receive clock failed");
    return std::uint64_t(ts.tv_sec) * 1000000000ULL + ts.tv_nsec;
}
// One synchronous receive call. Buffered deliveries have no arrival timestamp here.
struct ReceiveTrace {
    std::uint64_t begin_ns{}, delivery_ns{};
    std::uint32_t bytes{}, callbacks{}, buffered_callbacks{};
    std::uint8_t transport{};
    std::uint64_t connection_id{};
    bool measure_delivery{true}; // Timestamp the first direct callback; exclude buffered releases.
};
inline void trace_delivery(ReceiveTrace *trace, bool buffered = false) {
    if (!trace || !trace->measure_delivery)
        return;
    if (buffered) {
        ++trace->buffered_callbacks;
        return;
    }
    if (!trace->callbacks++)
        trace->delivery_ns = receive_clock_ns();
}
// Restores the borrowed trace even if application callbacks throw.
class ReceiveTraceScope {
  public:
    ReceiveTraceScope(ReceiveTrace *&slot, ReceiveTrace *value) : slot_(slot), old_(slot) {
        slot = value;
    }
    ~ReceiveTraceScope() { slot_ = old_; }
    ReceiveTraceScope(ReceiveTraceScope const &) = delete;
    ReceiveTraceScope &operator=(ReceiveTraceScope const &) = delete;

  private:
    ReceiveTrace *&slot_;
    ReceiveTrace *old_;
};
} // namespace protocol
