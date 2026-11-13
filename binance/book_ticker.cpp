#include "book_ticker.hpp"
#include <algorithm>
namespace binance {
namespace {
std::optional<Decimal> decimal(std::string_view text) {
    Decimal out;
    bool dot = false, digit = false, fraction = false;
    for (char c : text) {
        if (c == '.' and not dot and digit) {
            dot = true;
            continue;
        }
        if (c < '0' or c > '9')
            return std::nullopt;
        auto n = unsigned(c - '0');
        if (out.mantissa > (UINT64_MAX - n) / 10)
            return std::nullopt;
        out.mantissa = out.mantissa * 10 + n;
        digit = true;
        if (dot) {
            ++out.scale;
            fraction = true;
        }
    }
    if (not digit or (dot and not fraction) or out.scale > 18)
        return std::nullopt;
    return out;
}
// Minimal cursor over one JSON document; every helper fails closed.
struct Cursor {
    char const *p, *end;
    void space() noexcept {
        while (p != end and (*p == ' ' or *p == '\t' or *p == '\n' or *p == '\r'))
            ++p;
    }
    bool eat(char c) noexcept {
        space();
        if (p == end or *p != c)
            return false;
        ++p;
        return true;
    }
    // A one-letter key exactly, followed by ':'. Escaped keys never match.
    bool key(char k) noexcept {
        space();
        if (end - p < 3 or p[0] != '"' or p[1] != k or p[2] != '"')
            return false;
        p += 3;
        return eat(':');
    }
    bool peek_key(char k) noexcept {
        space();
        return end - p >= 3 and p[0] == '"' and p[1] == k and p[2] == '"';
    }
    // Unescaped string body; control characters and backslashes are rejected.
    bool string(std::string_view &out) noexcept {
        if (not eat('"'))
            return false;
        auto begin = p;
        while (p != end and *p != '"') {
            if (*p == '\\' or static_cast<unsigned char>(*p) < 0x20)
                return false;
            ++p;
        }
        if (p == end)
            return false;
        out = {begin, static_cast<std::size_t>(p - begin)};
        ++p;
        return true;
    }
    // JSON non-negative integer without fraction/exponent; no leading zeros; fits uint64.
    bool uint(std::uint64_t &out) noexcept {
        space();
        if (p == end or *p < '0' or *p > '9')
            return false;
        if (*p == '0' and end - p > 1 and p[1] >= '0' and p[1] <= '9')
            return false;
        std::uint64_t value{};
        while (p != end and *p >= '0' and *p <= '9') {
            auto digit = unsigned(*p - '0');
            if (value > (UINT64_MAX - digit) / 10)
                return false;
            value = value * 10 + digit;
            ++p;
        }
        if (p != end and (*p == '.' or *p == 'e' or *p == 'E'))
            return false;
        out = value;
        return true;
    }
    // After a value: 1 for ',', 2 for '}', 0 otherwise.
    int next() noexcept {
        if (eat(','))
            return 1;
        return eat('}') ? 2 : 0;
    }
    bool finished() noexcept {
        space();
        return p == end;
    }
};
} // namespace
ParseResult BookTickerParser::parse(std::string_view json) const {
    if (json.size() > 65536)
        return {};
    Cursor c{json.data(), json.data() + json.size()};
    if (not c.eat('{'))
        return {};
    std::uint64_t ignored{};
    std::string_view text;
    if (c.peek_key('e')) {
        if (c.key('e') and c.string(text) and text == "serverShutdown" and c.next() == 1 and
            c.key('E') and c.uint(ignored) and c.next() == 1 and c.key('T') and
            c.uint(ignored) and c.next() == 2 and c.finished())
            return {MessageKind::Shutdown, {}};
        return {};
    }
    BookTicker quote;
    auto decimal_field = [&](char k, Decimal &out) {
        if (not c.key(k) or not c.string(text))
            return false;
        auto parsed = decimal(text);
        if (not parsed)
            return false;
        out = *parsed;
        return true;
    };
    if (not c.key('u') or not c.uint(quote.update_id) or c.next() != 1)
        return {};
    if (not c.key('s') or not c.string(text) or text != symbol_ or text.size() > 32 or
        c.next() != 1)
        return {};
    std::copy(text.begin(), text.end(), quote.symbol.begin());
    if (not decimal_field('b', quote.bid_price) or c.next() != 1 or
        not decimal_field('B', quote.bid_qty) or c.next() != 1 or
        not decimal_field('a', quote.ask_price) or c.next() != 1 or
        not decimal_field('A', quote.ask_qty))
        return {};
    auto state = c.next();
    // Optional replay extension: T then E, each at most once, in that order.
    if (state == 1 and c.peek_key('T')) {
        std::uint64_t t{};
        if (not c.key('T') or not c.uint(t))
            return {};
        quote.trade_ts = t;
        state = c.next();
    }
    if (state == 1 and c.peek_key('E')) {
        std::uint64_t e{};
        if (not c.key('E') or not c.uint(e))
            return {};
        quote.event_ts = e;
        state = c.next();
    }
    if (state != 2 or not c.finished())
        return {};
    return {MessageKind::Quote, quote};
}
} // namespace binance
