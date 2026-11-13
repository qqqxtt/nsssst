#pragma once
#include "book_ticker.hpp"
#include "bench/stages.hpp"
#include "binance/kernel_resolver.hpp"
#include "wss/client.hpp"
#include <future>
namespace binance {
struct Config {
    std::string host{"stream.binance.com"}, symbol{"BTCUSDT"}, ca_file;
    std::uint16_t port{443};
    bool quiet{};
    bench::StageSamples *stats{}; // Borrowed; must outlive Connection.
    bool direct_tls{true};        // See wss::Config::direct_tls.
};
// Owns one asynchronous libc lookup at a time. Destruction joins an outstanding lookup.
class Connection {
  public:
    Connection(protocol::TcpManager &tcp, Config config);
    Connection(Connection const &) = delete;
    Connection &operator=(Connection const &) = delete;
    Connection(Connection &&) = delete;
    Connection &operator=(Connection &&) = delete;
    void poll(protocol::TcpManager::Clock::time_point now);
    void disconnected(std::string_view reason);
    bool input_ready() const noexcept { return client_ && client_->input_ready(); }
    protocol::TcpConnectionId connection_id() const noexcept {
        return client_ ? client_->connection_id() : 0;
    }
    std::optional<BookTicker> quote() const { return valid_ ? latest_ : std::nullopt; }
    // Idle cache warm-up: parses a cached quote and runs the TLS decrypt path. No state change.
    void warm();

  private:
    protocol::TcpManager &tcp_;
    Config config_;
    BookTickerParser parser_;
    std::unique_ptr<wss::Client> client_;
    std::future<std::vector<protocol::Ipv4Address>> resolving_;
    std::vector<protocol::Ipv4Address> addresses_;
    std::size_t address_{};
    unsigned failures_{}, attempts_{};
    std::uint64_t invalid_{};
    bool valid_{}, restart_{};
    std::optional<BookTicker> latest_;
    std::string warm_json_;
    protocol::TcpManager::Clock::time_point retry_{}, printed_{}, started_{}, last_invalid_{};
};
} // namespace binance
