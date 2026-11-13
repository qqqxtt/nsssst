#pragma once
#include "latency.hpp"
#include "protocol/receive_trace.hpp"
#include <array>
#include <span>
namespace bench {
enum class Stage { PacketToTcp, Tls, Json };
struct StageSample {
    // gap_ns: begin minus the previous valid begin of the same stage (0 for the first).
    std::uint64_t elapsed_ns{}, bytes{}, connection_id{}, gap_ns{};
};
// Samples arriving within this gap of the previous one run on a warm cache/branch state.
inline constexpr std::uint64_t hot_gap_ns = 100000;
// Each stage owns bounded storage, with independent warmup and overflow accounting.
class StageSamples {
  public:
    StageSamples(std::size_t capacity, std::size_t warmup, bool tcp_only = false)
        : warmup_(warmup), tcp_only_(tcp_only) {
        for (unsigned i = 0; i < (tcp_only_ ? 1U : 3U); ++i)
            stages_[i].values.resize(capacity);
        if (!tcp_only_)
            quotes_.resize(capacity);
    }
    // End-to-end log: the receive loop marks each packet before stack processing; a quote
    // completed while handling that packet is logged with it. Joined offline with the
    // sender's CSV (both sides use CLOCK_MONOTONIC on the same kernel).
    void packet_started(std::uint64_t ns) noexcept { last_packet_ns_ = ns; }
    void record_quote(std::uint64_t update_id, std::uint64_t done_ns) noexcept {
        if (quote_size_ == quotes_.size()) {
            ++quote_overflow_;
            return;
        }
        quotes_[quote_size_++] = {update_id, last_packet_ns_, done_ns};
    }
    StageSamples(StageSamples const &) = delete;
    StageSamples &operator=(StageSamples const &) = delete;
    // One sample per input packet, ending before its first direct TCP callback.
    // Buffered releases have no direct callback timestamp of their own.
    void record_packet(protocol::ReceiveTrace const &trace) noexcept {
        if (trace.transport == 6 && trace.callbacks && trace.delivery_ns)
            record(Stage::PacketToTcp, trace.begin_ns, trace.delivery_ns,
                   trace.bytes, trace.connection_id);
    }
    void record(Stage stage, std::uint64_t begin, std::uint64_t end, std::size_t bytes,
                std::uint64_t connection_id) noexcept {
        if (tcp_only_ && stage != Stage::PacketToTcp) return;
        auto &s = stages_[static_cast<unsigned>(stage)];
        if (!begin || end < begin) {
            ++s.invalid;
            return;
        }
        auto gap = s.last_begin && begin >= s.last_begin ? begin - s.last_begin : 0;
        s.last_begin = begin;
        if (++s.seen <= warmup_)
            return;
        if (s.size == s.values.size()) {
            ++s.overflow;
            return;
        }
        s.values[s.size++] = {end - begin, bytes, connection_id, gap};
    }
    std::span<StageSample const> samples(Stage stage) const noexcept {
        auto const &s = stages_[static_cast<unsigned>(stage)];
        return {s.values.data(), s.size};
    }
    std::uint64_t overflow(Stage stage) const noexcept {
        return stages_[static_cast<unsigned>(stage)].overflow;
    }
    void report(std::string const &prefix) const {
        constexpr std::array names{"packet_to_tcp", "tls", "json"};
        for (unsigned i = 0; i < (tcp_only_ ? 1U : 3U); ++i) {
            auto const &s = stages_[i];
            std::printf("stage=%s seen=%llu warmup=%zu overflow=%llu invalid=%llu\n", names[i],
                        static_cast<unsigned long long>(s.seen), warmup_,
                        static_cast<unsigned long long>(s.overflow),
                        static_cast<unsigned long long>(s.invalid));
            std::vector<std::uint64_t> durations, hot, cold;
            durations.reserve(s.size);
            for (auto const &sample : samples(static_cast<Stage>(i))) {
                durations.push_back(sample.elapsed_ns);
                (sample.gap_ns < hot_gap_ns ? hot : cold)
                    .push_back(sample.elapsed_ns);
            }
            summarize(names[i], std::move(durations));
            // Hot: previous sample < 100 us earlier. Cold: idle gap first; mostly cache misses.
            summarize((std::string(names[i]) + ".hot").c_str(), std::move(hot));
            summarize((std::string(names[i]) + ".cold").c_str(), std::move(cold));
            std::ofstream out(prefix + "." + names[i] + ".csv");
            out.exceptions(std::ios::badbit | std::ios::failbit);
            out << "elapsed_ns,bytes,connection_id,gap_ns\n";
            for (auto const &v : samples(static_cast<Stage>(i)))
                out << v.elapsed_ns << ',' << v.bytes << ',' << v.connection_id << ',' << v.gap_ns
                    << '\n';
        }
        if (quote_size_) {
            std::printf("quotes: n=%zu overflow=%llu -> %s.quotes.csv\n", quote_size_,
                        static_cast<unsigned long long>(quote_overflow_), prefix.c_str());
            std::ofstream out(prefix + ".quotes.csv");
            out.exceptions(std::ios::badbit | std::ios::failbit);
            out << "update_id,rx_ns,done_ns\n";
            for (std::size_t i = 0; i < quote_size_; ++i)
                out << quotes_[i].update_id << ',' << quotes_[i].rx_ns << ',' << quotes_[i].done_ns
                    << '\n';
        }
    }

  private:
    struct Storage {
        std::vector<StageSample> values;
        std::size_t size{};
        std::uint64_t seen{}, overflow{}, invalid{}, last_begin{};
    };
    std::array<Storage, 3> stages_;
    struct Quote {
        std::uint64_t update_id, rx_ns, done_ns;
    };
    std::vector<Quote> quotes_;
    std::size_t quote_size_{};
    std::uint64_t quote_overflow_{}, last_packet_ns_{};
    std::size_t warmup_;
    bool tcp_only_;
};
} // namespace bench
