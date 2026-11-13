#include "client.hpp"
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <openssl/rand.h>
#include <string_view>
namespace wss {
using protocol::Bytes;
namespace {
std::string lower(std::string s) {
    for (auto &c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}
bool token(std::string s, std::string_view want) {
    s = lower(s);
    std::size_t p{};
    while (p < s.size()) {
        auto e = s.find(',', p);
        auto v = std::string_view(s).substr(p, e == s.npos ? s.size() - p : e - p);
        while (not v.empty() and v.front() == ' ')
            v.remove_prefix(1);
        while (not v.empty() and v.back() == ' ')
            v.remove_suffix(1);
        if (v == want)
            return true;
        if (e == s.npos)
            break;
        p = e + 1;
    }
    return false;
}
bool utf8(Bytes<> b) {
    std::uint32_t value{}, minimum{};
    unsigned needed{};
    for (auto c : b) {
        if (needed) {
            if ((c & 0xc0) != 0x80)
                return false;
            value = (value << 6) | (c & 63);
            if (--needed == 0 and
                (value < minimum or value > 0x10ffff or (value >= 0xd800 and value <= 0xdfff)))
                return false;
        } else if (c < 128)
            continue;
        else if (c >= 0xc2 and c <= 0xdf) {
            needed = 1;
            value = c & 31;
            minimum = 128;
        } else if (c >= 0xe0 and c <= 0xef) {
            needed = 2;
            value = c & 15;
            minimum = 2048;
        } else if (c >= 0xf0 and c <= 0xf4) {
            needed = 3;
            value = c & 7;
            minimum = 65536;
        } else
            return false;
    }
    return needed == 0;
}
} // namespace
void Client::frame(unsigned opcode, Bytes<> bytes) {
    if (plain_.size() + bytes.size() + 14 > 131072)
        fail("WS output limit");
    std::array<unsigned char, 4> mask{};
    if (RAND_bytes(mask.data(), 4) != 1)
        fail("mask random");
    plain_.push_back(0x80 | opcode);
    if (bytes.size() < 126)
        plain_.push_back(0x80 | bytes.size());
    else if (bytes.size() <= 65535) {
        plain_.push_back(0xfe);
        plain_.push_back(bytes.size() >> 8);
        plain_.push_back(bytes.size());
    } else {
        plain_.push_back(0xff);
        for (int i = 7; i >= 0; --i)
            plain_.push_back(std::uint64_t(bytes.size()) >> (8 * i));
    }
    plain_.insert(plain_.end(), mask.begin(), mask.end());
    for (std::size_t i = 0; i < bytes.size(); ++i)
        plain_.push_back(bytes[i] ^ mask[i % 4]);
}
void Client::parse() {
    if (state_ == State::Upgrade) {
        auto bytes = received();
        std::string text(bytes.begin(), bytes.end());
        auto end = text.find("\r\n\r\n");
        if (end == text.npos) {
            if (text.size() > 8192)
                fail("HTTP header limit");
            return;
        }
        if (end > 8192 or text.substr(0, 13) != "HTTP/1.1 101 ")
            fail("HTTP upgrade status");
        std::map<std::string, std::string> fields;
        auto p = text.find("\r\n") + 2;
        while (p < end) {
            auto e = text.find("\r\n", p);
            auto colon = text.find(':', p);
            if (colon >= e)
                fail("HTTP header");
            auto name = lower(text.substr(p, colon - p));
            auto value = text.substr(colon + 1, e - colon - 1);
            auto first = value.find_first_not_of(" \t");
            value = first == value.npos ? "" : value.substr(first);
            while (not value.empty() and (value.back() == ' ' or value.back() == '\t'))
                value.pop_back();
            if (not fields.emplace(name, value).second)
                fail("duplicate HTTP header");
            p = e + 2;
        }
        if (not token(fields["upgrade"], "websocket") or
            not token(fields["connection"], "upgrade") or
            fields["sec-websocket-accept"] != expected_ or
            fields.contains("sec-websocket-extensions") or
            fields.contains("sec-websocket-protocol"))
            fail("HTTP upgrade validation");
        consume_input(end + 4);
        state_ = State::Open;
        if (config_.echo_probe)
            frame(1, Bytes<>{reinterpret_cast<unsigned char const *>(config_.message.data()),
                             config_.message.size()});
    }
    while ((state_ == State::Open or state_ == State::Closing) and received().size() >= 2) {
        auto b = received();
        unsigned opcode = b[0] & 15;
        bool fin = b[0] & 128;
        std::uint64_t n = b[1] & 127;
        std::size_t h = 2;
        if ((b[0] & 0x70) or (b[1] & 128))
            fail("WS flags/mask");
        if (n == 126) {
            if (b.size() < 4)
                return;
            n = (unsigned(b[2]) << 8) | b[3];
            h = 4;
            if (n < 126)
                fail("WS length");
        } else if (n == 127) {
            if (b.size() < 10)
                return;
            if (b[2] & 128)
                fail("WS length overflow");
            n = 0;
            for (unsigned i = 2; i < 10; ++i)
                n = (n << 8) | b[i];
            h = 10;
            if (n <= 65535)
                fail("WS length");
        }
        if (n > 65536 or (opcode >= 8 and (not fin or n > 125)))
            fail("WS size/control");
        if (b.size() < h + n)
            return;
        Bytes<> payload{b.data() + h, static_cast<std::size_t>(n)};
        if (opcode == 9)
            frame(10, payload);
        else if (opcode == 10) {
        } else if (opcode == 8) {
            if (config_.echo_probe and not echo_verified_)
                fail("closed without echo");
            if (n == 1)
                fail("WS close payload");
            if (n >= 2) {
                unsigned code = (payload[0] << 8) | payload[1];
                if (code < 1000 or code >= 5000 or (code >= 1004 and code <= 1006) or
                    code == 1015 or (code >= 1016 and code < 3000) or not utf8(payload.subspan(2)))
                    fail("WS close code/UTF8");
            }
            if (not sent_close_) {
                frame(8, payload);
                sent_close_ = true;
            }
            deadline_ = protocol::TcpManager::Clock::now() + std::chrono::seconds(15);
            peer_close_ = true;
            state_ = State::Closing;
        } else if (opcode <= 2) {
            if ((opcode == 0 and fragment_ == 0) or (opcode != 0 and fragment_ != 0))
                fail("WS continuation");
            bool direct = opcode != 0 && fin && !config_.echo_probe;
            if (opcode)
                fragment_ = opcode;
            if (message_.size() + n > 65536)
                fail("WS message limit");
            if (!direct) message_.insert(message_.end(), payload.begin(), payload.end());
            if (fin) {
                auto content = direct ? payload : Bytes<>{message_};
                if (fragment_ == 1 and not utf8(content))
                    fail("WS text UTF8");
                if (config_.echo_probe) {
                    if (message_.size() != config_.message.size() or
                        not std::equal(
                            message_.begin(), message_.end(),
                            reinterpret_cast<unsigned char const *>(config_.message.data())))
                        fail("echo mismatch");
                    echo_verified_ = true;
                    std::puts("WSS echo verified");
                } else if (config_.on_message) {
                    config_.on_message(content); // Unfragmented messages are not copied.
                }
                message_.clear();
                fragment_ = 0;
                if (config_.echo_probe and not sent_close_) {
                    std::array<unsigned char, 2> code{3, 232};
                    frame(8, code);
                    sent_close_ = true;
                    state_ = State::Closing;
                }
            }
        } else
            fail("WS opcode");
        consume_input(h + static_cast<std::size_t>(n));
    }
}
} // namespace wss
