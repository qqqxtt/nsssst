// nsst: single-threaded DPDK receive loop driving a user-space TCP/IP stack.
// Modes (environment variables, see README):
//   listen  (default)            TCP and UDP port 19000, ICMP echo, ARP
//   market  BINANCE_SYMBOL=...   TLS 1.3 WebSocket BookTicker subscription with stage timing
//   tcp     BENCH_TCP_ONLY=1     listen on TCP 19000 and time packet -> TCP delivery only
#include "bench/stages.hpp"
#include "binance/connection.hpp"
#include "dpdk/runtime.hpp"
#include "protocol/stack.hpp"
#include "protocol/udp_registry.hpp"

#include <atomic>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>

namespace {

std::atomic<bool> stop_requested{false};
void request_stop(int) noexcept { stop_requested.store(true, std::memory_order_relaxed); }

protocol::Ipv4Address parse_ip(std::string_view text) {
    protocol::Ipv4Address ip{};
    for (std::size_t i = 0; i < ip.size(); ++i) {
        auto end = text.find('.');
        if ((i == 3) != (end == std::string_view::npos))
            throw std::invalid_argument("expected dotted IPv4 address");
        auto part = text.substr(0, end);
        unsigned value{};
        auto parsed = std::from_chars(part.data(), part.data() + part.size(), value);
        if (part.empty() or parsed.ec != std::errc{} or parsed.ptr != part.data() + part.size() or
            value > 255)
            throw std::invalid_argument("invalid IPv4 address");
        ip[i] = static_cast<unsigned char>(value);
        if (i != 3)
            text.remove_prefix(end + 1);
    }
    if (not protocol::valid_peer_ip(ip))
        throw std::invalid_argument("invalid unicast IPv4");
    return ip;
}

char const* env(char const* name) { return std::getenv(name); }

std::size_t env_number(char const* name, std::size_t fallback, std::size_t maximum) {
    auto raw = env(name);
    if (not raw)
        return fallback;
    std::string_view text{raw};
    std::size_t value{};
    auto r = std::from_chars(text.data(), text.data() + text.size(), value);
    if (text.empty() or r.ec != std::errc{} or r.ptr != text.data() + text.size() or
        value > maximum)
        throw std::invalid_argument(std::string("invalid ") + name);
    return value;
}

struct Options {
    protocol::Ipv4Address local_ip;
    std::optional<protocol::Ipv4Address> gateway;
    unsigned prefix_length;
    // Market mode.
    std::string symbol, host, ca_file;
    std::uint16_t port;
    bool direct_tls;
    // Measurement.
    bool tcp_only, stats, quiet, busy, idle_warm;
    std::size_t seconds, samples, warmup;
    std::string output_prefix;

    static Options from_environment() {
        Options o{};
        o.local_ip = parse_ip(env("LOCAL_IP") ? env("LOCAL_IP") : "192.0.2.2");
        if (env("GATEWAY_IP"))
            o.gateway = parse_ip(env("GATEWAY_IP"));
        o.prefix_length = static_cast<unsigned>(env_number("PREFIX_LENGTH", 24, 32));
        o.symbol = env("BINANCE_SYMBOL") ? env("BINANCE_SYMBOL") : "";
        o.host = env("BINANCE_HOST") ? env("BINANCE_HOST") : "stream.binance.com";
        o.ca_file = env("CA_FILE") ? env("CA_FILE") : "";
        o.port = static_cast<std::uint16_t>(env_number("BINANCE_PORT", 443, 65535));
        o.direct_tls = env_number("TLS_DIRECT", 1, 1);
        o.tcp_only = env_number("BENCH_TCP_ONLY", 0, 1);
        bool market = not o.symbol.empty();
        if (o.tcp_only and market)
            throw std::invalid_argument("BENCH_TCP_ONLY cannot be combined with BINANCE_SYMBOL");
        o.stats = o.tcp_only or env_number("BENCH_STAGES", market, 1);
        if (o.stats and not o.tcp_only and not market)
            throw std::invalid_argument("BENCH_STAGES requires BINANCE_SYMBOL");
        o.quiet = env_number("BENCH_QUIET", o.stats, 1);
        o.busy = env_number("BENCH_BUSY_POLL", o.stats, 1);
        // Warm-up only makes sense while busy-polling; it would keep a sleeping core awake.
        o.idle_warm = o.busy and env_number("IDLE_WARM", 1, 1);
        o.seconds = env_number("BENCH_SECONDS", o.stats ? 60 : 0, 86400);
        o.samples = env_number("BENCH_SAMPLES", 100000, 1000000);
        o.warmup = env_number("BENCH_WARMUP", 100, 10000000);
        o.output_prefix = env("BENCH_OUTPUT_PREFIX") ? env("BENCH_OUTPUT_PREFIX") : "stages";
        if (o.port == 0)
            throw std::invalid_argument("invalid BINANCE_PORT");
        return o;
    }
};

// Ends the ACK-coalescing window even when packet processing throws.
class AckBatch {
  public:
    explicit AckBatch(protocol::Stack& stack) noexcept
        : stack_(stack) {
        stack_.begin_batch();
    }
    ~AckBatch() noexcept {
        try {
            stack_.end_batch();
        } catch (...) {
            std::fputs("ACK batch flush failed\n", stderr);
        }
    }
    AckBatch(AckBatch const&) = delete;
    AckBatch& operator=(AckBatch const&) = delete;

  private:
    protocol::Stack& stack_;
};

void receive_loop(Options const& options, dpdk::EthPort const& port, dpdk::TxQueue& tx,
    protocol::Stack& stack, binance::Connection* market, bench::StageSamples* stats) {
    using Clock = protocol::TcpManager::Clock;
    // Timers in the stack and the market client have >= 1 s granularity. While the port is
    // idle, run them every 50 us instead of on every rx_burst so the empty loop stays small
    // and the receive path keeps its instruction cache, branch history and TLB entries.
    constexpr auto maintenance_interval = std::chrono::microseconds{50};
    auto const begin = Clock::now();
    auto const limit = std::chrono::seconds(options.seconds);
    auto next_maintenance = begin;
    bool active = true;   // The previous burst carried packets: replies may be waiting.
    unsigned warm_sink{}; // Consumes warm-up results so they are not optimised away.
    auto disconnected = [&](std::exception const& e) {
        if (not market)
            throw;
        market->disconnected(e.what());
    };
    std::printf("Receiving on port %u; press Ctrl+C to stop.\n", unsigned(port.id()));
    std::fflush(stdout);
    while (not stop_requested.load(std::memory_order_relaxed)) {
        auto const now = Clock::now(); // The single clock read for this iteration.
        if (options.seconds and now - begin >= limit)
            break;
        if (active or now >= next_maintenance) {
            try {
                stack.poll(now);
            } catch (std::exception const& e) {
                disconnected(e);
            }
            if (market)
                market->poll(now);
            if (options.idle_warm and not active) {
                // Keep the RX/TLS/JSON code and key schedule cached while the port is idle.
                warm_sink += stack.warm();
                if (market)
                    market->warm();
            }
            next_maintenance = now + maintenance_interval;
        }
        tx.flush();
        dpdk::RxBatch batch{port};
        if (batch.packets().empty()) {
            active = false;
            if (not options.busy)
                std::this_thread::sleep_for(std::chrono::milliseconds{1});
            continue;
        }
        active = true;
        {
            AckBatch acks{stack}; // One cumulative ACK per connection for this burst.
            for (auto* packet : batch.packets()) {
                try {
                    protocol::ReceiveTrace trace{.bytes = packet->pkt_len};
                    trace.begin_ns = stats ? bench::now_ns() : 0;
                    if (stats)
                        stats->packet_started(trace.begin_ns);
                    stack.receive(*packet, now, stats ? &trace : nullptr);
                    if (stats)
                        stats->record_packet(trace);
                    // TCP callbacks have returned: TLS may now safely write to TCP.
                    if (market and market->input_ready())
                        market->poll(now);
                } catch (std::exception const& e) {
                    disconnected(e);
                }
            }
        }
        tx.flush(); // Send the coalesced ACKs without waiting for the next burst.
    }
    static unsigned volatile sink;
    sink = warm_sink;
}

} // namespace

int main(int argc, char** argv) {
    try {
        auto options = Options::from_environment();
        dpdk::SignalHandler interrupt{SIGINT, request_stop};
        dpdk::SignalHandler terminate{SIGTERM, request_stop};
        dpdk::EAL eal{argc, argv};
        auto pool = dpdk::create_mempool();
        dpdk::EthPort port{0};
        port.start(*pool);
        dpdk::TxQueue tx{port, *pool};

        std::unique_ptr<bench::StageSamples> stats;
        if (options.stats)
            stats = std::make_unique<bench::StageSamples>(
                options.samples, options.warmup, options.tcp_only);
        bool verbose = not options.stats;
        protocol::UdpPortRegistry udp_ports;
        udp_ports.register_port(19000, [verbose](protocol::UdpDatagramView const& datagram,
                                           protocol::UdpReplySender const& reply) {
            if (not verbose)
                return;
            std::printf("UDP echo %u -> %u data=%u bytes\n", unsigned(datagram.source.port),
                unsigned(datagram.destination.port), unsigned(datagram.payload.length));
            if (not reply.send(datagram.payload))
                std::fputs("UDP reply rejected by TX queue\n", stderr);
        });
        udp_ports.freeze();

        protocol::StackConfig config{{dpdk::mac_address(port), options.local_ip}, options.gateway,
            options.prefix_length, options.quiet};
        protocol::Stack stack{
            config, udp_ports, [&tx](protocol::Bytes<> frame) { return tx.enqueue(frame); }};
        stack.tcp().listen(19000, {.on_data = [verbose](auto id, protocol::PacketSlice data) {
            if (verbose)
                std::printf("TCP connection=%llu received=%u bytes\n",
                    static_cast<unsigned long long>(id), data.length);
        }});
        stack.start();

        std::unique_ptr<binance::Connection> market;
        if (not options.symbol.empty())
            market = std::make_unique<binance::Connection>(
                stack.tcp(), binance::Config{options.host, options.symbol, options.ca_file,
                                 options.port, options.quiet, stats.get(), options.direct_tls});
        std::printf("runtime: busy_poll=%d duration=%zus tls_direct=%d idle_warm=%d\n",
            options.busy, options.seconds, options.direct_tls, options.idle_warm);
        receive_loop(options, port, tx, stack, market.get(), stats.get());
        tx.flush();
        if (stats)
            stats->report(options.output_prefix);
        // Stack and callbacks are destroyed before the port, mempool and EAL.
        return EXIT_SUCCESS;
    } catch (std::exception const& error) {
        std::fprintf(stderr, "%s\n", error.what());
        return EXIT_FAILURE;
    }
}
