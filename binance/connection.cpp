#include "connection.hpp"
#include <algorithm>
#include <cctype>
#include <cstdio>
namespace binance {
Connection::Connection(protocol::TcpManager &tcp, Config config)
    : tcp_(tcp), config_(std::move(config)), parser_(config_.symbol) {
    if (config_.symbol.empty() or config_.symbol.size() > 32 or
        not std::all_of(config_.symbol.begin(), config_.symbol.end(), [](unsigned char c) {
            return (c >= 'A' and c <= 'Z') or (c >= '0' and c <= '9');
        }))
        throw std::invalid_argument("expected uppercase ASCII Binance symbol");
    warm_json_ = R"({"u":1,"s":")" + config_.symbol +
                 R"(","b":"67000.01000000","B":"0.50000000","a":"67000.02000000","A":"1.25000000"})";
    if (parser_.parse(warm_json_).kind != MessageKind::Quote)
        throw std::logic_error("warm-up quote must parse");
}
void Connection::warm() {
    (void)parser_.parse(warm_json_);
    if (client_)
        client_->warm();
}
void Connection::disconnected(std::string_view reason) {
    std::fprintf(stderr, "Binance disconnected: %.*s\n",
                 int(std::min<std::size_t>(reason.size(), 512)), reason.data());
    client_.reset();
    valid_ = false;
    restart_ = false;
    retry_ =
        protocol::TcpManager::Clock::now() + std::chrono::seconds(1U << std::min(failures_++, 5U));
}
void Connection::poll(protocol::TcpManager::Clock::time_point now) {
    try {
        if (client_) {
            if (now - started_ >= std::chrono::minutes(1430)) {
                disconnected("scheduled 24h rotation");
                return;
            }
            client_->poll(now);
            if (restart_ or client_->done())
                disconnected("server shutdown/close");
            return;
        }
        if (now < retry_)
            return;
        if (resolving_.valid()) {
            if (resolving_.wait_for(std::chrono::seconds(0)) != std::future_status::ready)
                return;
            addresses_ = resolving_.get();
            address_ = 0;
        }
        if (address_ >= addresses_.size()) {
            addresses_.clear();
            address_ = 0;
            resolving_ = std::async(std::launch::async,
                                    [host = config_.host] { return binance::resolve_ipv4(host); });
            return;
        }
        auto ip = addresses_[address_++];
        std::string symbol = config_.symbol;
        for (auto &c : symbol)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        auto local = static_cast<std::uint16_t>(40000 + (attempts_++ % 20000));
        started_ = now;
        client_ = std::make_unique<wss::Client>(
            tcp_,
            wss::Config{
                .tcp = {ip, local, config_.port, {}},
                .hostname = config_.host,
                .path = "/ws/" + symbol + "@bookTicker",
                .ca_file = config_.ca_file,
                .port = config_.port,
                .message = "",
                .echo_probe = false,
                .on_message = [this](protocol::Bytes<> message) {
                    auto t0 = config_.stats ? bench::now_ns() : 0;
                    auto result = parser_.parse(
                        {reinterpret_cast<char const *>(message.data()), message.size()});
                    auto t1 = config_.stats ? bench::now_ns() : 0;
                    if (config_.stats) config_.stats->record(bench::Stage::Json, t0, t1, message.size(),
                                                          connection_id());
                    if (result.kind == MessageKind::Shutdown) {
                        restart_ = true;
                        return;
                    }
                    if (result.kind != MessageKind::Quote) {
                        ++invalid_;
                        auto now = protocol::TcpManager::Clock::now();
                        if (now - last_invalid_ >= std::chrono::seconds(30)) {
                            std::fprintf(stderr, "Binance invalid/unsupported JSON: %llu total\n",
                                         static_cast<unsigned long long>(invalid_));
                            last_invalid_ = now;
                        }
                        return;
                    }
                    if (valid_ and latest_ and result.quote.update_id <= latest_->update_id) {
                        return;
                    }
                    if (config_.stats)
                        config_.stats->record_quote(result.quote.update_id, t1);
                    result.quote.received_at = protocol::TcpManager::Clock::now();
                    latest_ = result.quote;
                    valid_ = true;
                    failures_ = 0;
                    auto now = protocol::TcpManager::Clock::now();
                    if (not config_.quiet and now - printed_ >= std::chrono::seconds(1)) {
                        std::printf("Binance %s u=%llu bid=%llu e-%u ask=%llu e-%u\n",
                                    config_.symbol.c_str(),
                                    static_cast<unsigned long long>(latest_->update_id),
                                    static_cast<unsigned long long>(latest_->bid_price.mantissa),
                                    latest_->bid_price.scale,
                                    static_cast<unsigned long long>(latest_->ask_price.mantissa),
                                    latest_->ask_price.scale);
                        printed_ = now;
                    }
                },
                .stats = config_.stats,
                .direct_tls = config_.direct_tls});
    } catch (std::exception const &error) {
        disconnected(error.what());
    }
}
} // namespace binance
