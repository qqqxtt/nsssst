#pragma once
#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
namespace binance {
struct Decimal {
    std::uint64_t mantissa{};
    unsigned scale{};
    bool operator==(Decimal const &) const = default;
};
struct BookTicker {
    std::array<char, 33> symbol{}; // Owned, NUL-terminated; at most 32 ASCII characters.
    std::optional<std::uint64_t> trade_ts, event_ts; // Exchange milliseconds; absent in Spot.
    std::uint64_t update_id{};
    Decimal bid_price, bid_qty, ask_price, ask_qty;
    std::chrono::steady_clock::time_point received_at{};
};
enum class MessageKind { Quote, Shutdown, Invalid };
struct ParseResult {
    MessageKind kind{MessageKind::Invalid};
    BookTicker quote;
};
// Hand-written scanner for exactly this schema: fixed field order, no key lookup, no heap.
// JSON escape sequences inside string values are rejected (Binance never sends them).
class BookTickerParser {
  public:
    explicit BookTickerParser(std::string symbol) : symbol_(std::move(symbol)) {}
    ParseResult parse(std::string_view json) const;

  private:
    std::string symbol_;
};
} // namespace binance
