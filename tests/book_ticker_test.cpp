#include "binance/book_ticker.hpp"
#include "binance/kernel_resolver.hpp"
#include <algorithm>
#include <cstdio>
#include <stdexcept>
using namespace binance;
void check(bool b) {
    if (not b)
        throw std::runtime_error("book ticker test failed");
}
int main() {
    BookTickerParser parser("BTCUSDT");
    auto kind = [&](std::string const &text) { return parser.parse(text).kind; };
    auto invalid = [&](std::string const &text) { return kind(text) == MessageKind::Invalid; };

    // Only the canonical field order u,s,b,B,a,A is accepted: 719 permutations are rejected.
    std::array<std::string, 6> fields{R"("u":18446744073709551615)", R"("s":"BTCUSDT")",
                                      R"("b":"1.2300")",            R"("B":"0.0001")",
                                      R"("a":"2.00")",              R"("A":"5")"};
    std::array<unsigned, 6> order{0, 1, 2, 3, 4, 5};
    do {
        std::string json = "{";
        for (auto i : order)
            json += (json.size() > 1 ? "," : "") + fields[i];
        json += '}';
        auto r = parser.parse(json);
        if (order != std::array<unsigned, 6>{0, 1, 2, 3, 4, 5}) {
            check(r.kind == MessageKind::Invalid);
            continue;
        }
        check(r.kind == MessageKind::Quote and r.quote.update_id == UINT64_MAX);
        check(std::string_view(r.quote.symbol.data()) == "BTCUSDT");
        check(!r.quote.trade_ts && !r.quote.event_ts);
        check(r.quote.bid_price == Decimal{12300, 4} and r.quote.ask_qty == Decimal{5, 0});
    } while (std::next_permutation(order.begin(), order.end()));

    std::string valid = R"({"u":1,"s":"BTCUSDT","b":"1","B":"2","a":"3","A":"4"})";
    auto with = [&](std::string tail) { return valid.substr(0, valid.size() - 1) + tail; };
    check(kind(valid) == MessageKind::Quote);
    check(kind(" \n{ \"u\" : 0 ,\"s\":\"BTCUSDT\",\"b\":\"1\",\"B\":\"2\",\"a\":\"3\",\"A\":\"4\" } \t") ==
          MessageKind::Quote);
    for (std::size_t n = 0; n < valid.size(); ++n) // every truncation
        check(invalid(valid.substr(0, n)));
    check(invalid(valid + " garbage"));
    check(invalid(R"({"u":1,"u":2,"s":"BTCUSDT","b":"1","B":"2","a":"3","A":"4"})"));
    check(invalid(R"({"u":1,"s":"ETHUSDT","b":"1","B":"2","a":"3","A":"4"})"));
    check(invalid(R"({"u":1,"s":"BTC\u0055SDT","b":"1","B":"2","a":"3","A":"4"})")); // escapes
    // Integers: no overflow, leading zeros, fractions or exponents.
    check(invalid(R"({"u":18446744073709551616,"s":"BTCUSDT","b":"1","B":"2","a":"3","A":"4"})"));
    check(invalid(R"({"u":01,"s":"BTCUSDT","b":"1","B":"2","a":"3","A":"4"})"));
    check(invalid(R"({"u":1.0,"s":"BTCUSDT","b":"1","B":"2","a":"3","A":"4"})"));
    check(invalid(R"({"u":1e3,"s":"BTCUSDT","b":"1","B":"2","a":"3","A":"4"})"));
    // Decimals are strings of digits with at most one dot; no sign, no overflow.
    check(invalid(R"({"u":1,"s":"BTCUSDT","b":"-1","B":"2","a":"3","A":"4"})"));
    check(invalid(R"({"u":1,"s":"BTCUSDT","b":1,"B":"2","a":"3","A":"4"})"));
    check(invalid(R"({"u":1,"s":"BTCUSDT","b":"18446744073709551616","B":"2","a":"3","A":"4"})"));
    // Optional replay timestamps: T then E, unsigned integers.
    auto timed = parser.parse(with(R"(,"T":123,"E":456})"));
    check(timed.kind == MessageKind::Quote && timed.quote.trade_ts == 123 &&
          timed.quote.event_ts == 456);
    auto event_only = parser.parse(with(R"(,"E":0})"));
    check(event_only.kind == MessageKind::Quote && !event_only.quote.trade_ts &&
          event_only.quote.event_ts == 0);
    check(invalid(with(R"(,"E":1,"T":2})")));
    check(invalid(with(R"(,"T":"123"})")));
    check(invalid(with(R"(,"E"6})")));
    check(invalid(with(R"(,"extra":1})")));
    // Control message.
    check(kind(R"({"e":"serverShutdown","E":10,"T":20})") == MessageKind::Shutdown);
    check(invalid(R"({"e":"something","E":10,"T":20})"));

    auto addresses = binance::resolve_ipv4("127.0.0.1");
    check(addresses.size() == 1 and addresses[0] == protocol::Ipv4Address{127, 0, 0, 1});
    std::puts("PASS: BookTicker fixed order, 719 rejected permutations, decimals, strict schema, "
              "timestamps, kernel resolver");
}
