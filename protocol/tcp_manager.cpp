#include "tcp_manager.hpp"
#include "tcp_sequence.hpp"
#include <algorithm>
#include <random>
#include <stdexcept>
namespace protocol {
namespace {
constexpr std::uint32_t window = 32768;
std::uint16_t peer_mss(TcpView const &tcp) {
    std::uint16_t mss = 536;
    auto options = tcp.options();
    for (std::size_t i = 0; i < options.size();) {
        auto kind = options[i];
        if (kind == 0)
            break;
        if (kind == 1) {
            ++i;
            continue;
        }
        if (kind == 2) {
            auto n = (unsigned(options[i + 2]) << 8) | options[i + 3];
            if (n)
                mss = std::min<unsigned>(536, n);
        }
        i += options[i + 1];
    }
    return mss;
}

bool valid_mac(MacAddress const &mac) { return valid_peer_mac(mac); }
} // namespace
TcpManager::TcpManager(LocalAddress local, Sender sender, Resolver resolver)
    : local_(local), sender_(std::move(sender)), resolver_(std::move(resolver)),
      next_iss_(std::random_device{}()) {}
void TcpManager::listen(std::uint16_t port, TcpCallbacks cb) {
    if (port == 0 or not cb.on_data or not listeners_.emplace(port, std::move(cb)).second)
        throw std::invalid_argument("invalid or duplicate TCP listener");
}
TcpConnectionId TcpManager::connect(TcpConnectOptions options, TcpCallbacks cb,
                                    Clock::time_point now) {
    if (not valid_peer_ip(options.peer) or options.peer == local_.ip or options.local_port == 0 or
        options.peer_port == 0 or not cb.on_data or
        (options.next_hop_mac and not valid_mac(*options.next_hop_mac)) or
        (not options.next_hop_mac and not resolver_))
        throw std::invalid_argument("invalid TCP connect options or no ARP resolver");
    Key key{options.peer, options.local_port, options.peer_port};
    if (sessions_.contains(key))
        throw std::invalid_argument("TCP connection already exists");
    if (sessions_.size() >= 128)
        throw std::runtime_error("TCP session limit reached");
    Session s{};
    s.id = next_id_++;
    s.state = State::Resolving;
    s.iss = next_iss_;
    next_iss_ += 65537;
    s.snd_una = s.iss;
    s.snd_nxt = s.iss + 1;
    s.activity = now;
    s.deadline = now + std::chrono::seconds(1);
    s.callbacks = std::move(cb);
    if (options.next_hop_mac) {
        s.mac = *options.next_hop_mac;
        s.state = State::SynSent;
    }
    auto it = sessions_.emplace(key, std::move(s)).first;
    if (it->second.state == State::SynSent)
        send_control(key, it->second);
    else
        resolve(key, it->second, now);
    return it->second.id;
}
bool TcpManager::resolve(Key const &key, Session &s, Clock::time_point now) {
    if (auto mac = resolver_(key.peer, now); mac and valid_mac(*mac)) {
        s.mac = *mac;
        s.state = State::SynSent;
        s.retries = 0;
        s.activity = now;
        s.deadline = now + std::chrono::seconds(1);
        send_control(key, s);
        return true;
    }
    return false;
}
TcpManager::Iterator TcpManager::find(TcpConnectionId id) {
    // At most 128 sessions: a linear scan is cheaper than keeping a second index in sync.
    return std::find_if(sessions_.begin(), sessions_.end(),
                        [id](auto const &entry) { return entry.second.id == id; });
}
TcpManager::ConstIterator TcpManager::find(TcpConnectionId id) const {
    return std::find_if(sessions_.begin(), sessions_.end(),
                        [id](auto const &entry) { return entry.second.id == id; });
}
std::size_t TcpManager::write(TcpConnectionId id, Bytes<> bytes) {
    auto it = find(id);
    if (it == sessions_.end())
        return 0;
    auto &s = it->second;
    if (s.close_requested or (s.state != State::Established and s.state != State::CloseWait))
        return 0;
    auto n = std::min<std::size_t>(bytes.size(), 65536 - s.tx.size());
    s.tx.insert(s.tx.end(), bytes.begin(), bytes.begin() + n);
    return n;
}
bool TcpManager::flushed(TcpConnectionId id) const {
    auto it = find(id);
    return it == sessions_.end() or it->second.tx.empty();
}
bool TcpManager::closed(TcpConnectionId id) const {
    auto it = find(id);
    return it == sessions_.end() or it->second.state == State::TimeWait;
}
void TcpManager::abort(TcpConnectionId id) noexcept {
    auto it = find(id);
    if (it == sessions_.end())
        return;
    auto &s = it->second;
    if (s.state == State::TimeWait) {
        s.callbacks = {};
        return;
    }
    if (s.state != State::Resolving and s.state != State::SynSent)
        try {
            send(it->first, s, 0x14, s.snd_nxt);
        } catch (...) { // Best-effort reset; local cleanup must still complete.
        }
    sessions_.erase(it);
}
void TcpManager::detach(TcpConnectionId id) {
    if (auto it = find(id); it != sessions_.end())
        it->second.callbacks = {};
}
bool TcpManager::close(TcpConnectionId id, Clock::time_point now) {
    auto it = find(id);
    if (it == sessions_.end())
        return false;
    auto &s = it->second;
    if (s.state != State::Established and s.state != State::CloseWait)
        return false;
    s.close_requested = true;
    pump_tx(it->first, s, now);
    return true;
}
void TcpManager::pump_tx(Key const &key, Session &s, Clock::time_point now) {
    if (s.state != State::Established and s.state != State::CloseWait)
        return;
    if (not s.tx.empty() and s.flight == 0) {
        // Conservative IPv4 default MSS; one segment in flight.
        auto n = std::min<std::size_t>({s.mss, s.tx.size(), s.peer_window});
        if (n) {
            s.flight = n;
            s.snd_nxt += n;
            s.retries = 0;
            s.deadline = now + std::chrono::seconds(1);
            send(key, s, 0x18, s.snd_una, Bytes<>{s.tx}.first(n));
        } else if (now >= s.deadline) {
            send(key, s, 0x10, s.snd_nxt - 1);
            s.deadline = now + std::chrono::seconds(1);
        }
    }
    if (s.tx.empty() and s.close_requested) {
        s.state = s.state == State::CloseWait ? State::LastAck : State::FinWait1;
        ++s.snd_nxt;
        s.retries = 0;
        s.activity = now;
        s.deadline = now + std::chrono::seconds(1);
        send_control(key, s);
    }
}
void TcpManager::finish(Iterator it, bool error) {
    auto cb = it->second.callbacks.on_closed;
    auto id = it->second.id;
    sessions_.erase(it);
    if (cb)
        cb(id, error);
}
void TcpManager::enter_time_wait(Session &s, Clock::time_point now) {
    s.state = State::TimeWait;
    s.pending.clear();
    s.deadline = now + std::chrono::seconds(120); // 2*MSL, with MSL=60s for this demo.
}
void TcpManager::send_control(Key const &key, Session const &s) {
    if (s.state == State::SynSent)
        send(key, s, 0x02, s.iss);
    else if (s.state == State::SynReceived)
        send(key, s, 0x12, s.iss);
    else
        send(key, s, 0x11, s.snd_nxt - 1);
}
std::size_t TcpManager::retained_segments() const {
    std::size_t count{};
    for (auto const &[key, s] : sessions_)
        for (auto const &f : s.pending)
            count += f.data.owner->nb_segs;
    return count;
}
// Segment arrival, RFC 9293 section 3.10.7. Each step returns false when the segment has
// been fully handled (dropped, answered or the session finished).
void TcpManager::receive(IPv4View const &ip, TcpView const &tcp, Bytes<6> mac,
                         Clock::time_point now, ReceiveTrace *trace) {
    ReceiveTraceScope scope{trace_, trace};
    Key key{};
    std::copy(ip.source().begin(), ip.source().end(), key.peer.begin());
    key.local_port = tcp.destination_port();
    key.peer_port = tcp.source_port();
    if (not std::equal(ip.destination().begin(), ip.destination().end(), local_.ip.begin()) or
        not valid_peer_ip(key.peer) or key.peer_port == 0 or (mac[0] & 1) != 0 or
        std::all_of(mac.begin(), mac.end(), [](auto b) { return b == 0; }))
        return;
    auto it = sessions_.find(key);
    if (it == sessions_.end()) {
        accept(key, tcp, mac, now);
        return;
    }
    auto &s = it->second;
    if (trace_)
        trace_->connection_id = s.id;
    if (s.state == State::Resolving)
        return;
    if (tcp.has_flag(TcpFlag::Syn))
        s.mss = peer_mss(tcp);
    // True when this very segment completed the three-way handshake.
    bool handshake = false;
    if (s.state == State::SynSent) {
        if (not syn_sent(it, tcp, now))
            return;
        handshake = true;
    }
    auto seq = unwrap(tcp.sequence_number(), s.next);
    if (s.state == State::TimeWait) {
        if (tcp.has_flag(TcpFlag::Fin) and seq + tcp.payload().length + 1 == s.next) {
            send(key, s, 0x10, s.snd_nxt); // Retransmitted FIN: ACK again, restart 2*MSL.
            s.deadline = now + std::chrono::seconds(120);
        }
        return;
    }
    if (tcp.has_flag(TcpFlag::Rst)) {
        if (seq == s.next)
            finish(it, true);
        else if (seq >= s.next and seq < s.next + window)
            send(key, s, 0x10, s.snd_nxt); // Challenge ACK (RFC 5961).
        return;
    }
    if (tcp.has_flag(TcpFlag::Syn) and not handshake) {
        if (not repeated_syn(key, s, tcp, seq))
            return;
        handshake = true;
    }
    auto data_seq = seq + (handshake ? 1 : 0);
    auto segment_length = tcp.payload().length + tcp.has_flag(TcpFlag::Fin);
    if (data_seq >= s.next + window or data_seq + segment_length < s.next) {
        send(key, s, 0x10, s.snd_nxt); // Outside the receive window.
        return;
    }
    if (not tcp.has_flag(TcpFlag::Ack) or
        (tcp.acknowledgment_number() - s.snd_una > s.snd_nxt - s.snd_una)) {
        send(key, s, 0x10, s.snd_nxt); // Missing ACK or acknowledges unsent data.
        return;
    }
    if (s.state == State::SynReceived) {
        if (tcp.acknowledgment_number() != s.snd_nxt or data_seq != s.next)
            return;
        s.state = State::Established;
        if (s.callbacks.on_open)
            s.callbacks.on_open(s.id);
    }
    if (acknowledge(it, tcp, now))
        deliver(key, s, tcp, handshake, now);
}
// No session: answer with RST, or create SYN_RECEIVED for a listener.
void TcpManager::accept(Key const &key, TcpView const &tcp, Bytes<6> mac, Clock::time_point now) {
    if (tcp.has_flag(TcpFlag::Rst))
        return;
    auto listener = listeners_.find(key.local_port);
    if (listener == listeners_.end() or tcp.has_flag(TcpFlag::Ack)) {
        Session reset{};
        std::copy(mac.begin(), mac.end(), reset.mac.begin());
        reset.next = std::uint64_t{tcp.sequence_number()} + tcp.payload().length +
                     tcp.has_flag(TcpFlag::Syn) + tcp.has_flag(TcpFlag::Fin);
        send(key, reset, tcp.has_flag(TcpFlag::Ack) ? 0x04 : 0x14,
             tcp.has_flag(TcpFlag::Ack) ? tcp.acknowledgment_number() : 0);
        return;
    }
    if ((tcp.flags() & 0x17) != 2 or sessions_.size() >= 128)
        return;
    Session s{};
    s.id = next_id_++;
    std::copy(mac.begin(), mac.end(), s.mac.begin());
    s.iss = next_iss_;
    next_iss_ += 65537;
    s.snd_una = s.iss;
    s.snd_nxt = s.iss + 1;
    s.mss = peer_mss(tcp);
    s.peer_iss = tcp.sequence_number();
    s.next = 0x100000000ULL + s.peer_iss + 1;
    s.activity = now;
    s.deadline = now + std::chrono::seconds(1);
    s.callbacks = listener->second;
    auto it = sessions_.emplace(key, std::move(s)).first;
    if (trace_)
        trace_->connection_id = it->second.id;
    send_control(key, it->second);
}
// Active open waiting for SYN+ACK. True when the connection became ESTABLISHED.
bool TcpManager::syn_sent(Iterator it, TcpView const &tcp, Clock::time_point now) {
    auto &s = it->second;
    // The peer's sequence space is unknown until its SYN. A refusal needs a valid ACK.
    bool ack = tcp.has_flag(TcpFlag::Ack);
    if (ack and tcp.acknowledgment_number() != s.snd_nxt)
        return false;
    if (tcp.has_flag(TcpFlag::Rst)) {
        if (ack)
            finish(it, true);
        return false;
    }
    if (not tcp.has_flag(TcpFlag::Syn) or tcp.has_flag(TcpFlag::Fin))
        return false;
    s.peer_iss = tcp.sequence_number();
    s.next = 0x100000000ULL + s.peer_iss + 1;
    s.activity = now;
    if (not ack) { // Simultaneous open.
        s.state = State::SynReceived;
        s.retries = 0;
        s.deadline = now + std::chrono::seconds(1);
        send_control(it->first, s);
        return false;
    }
    s.snd_una = s.snd_nxt;
    s.state = State::Established;
    if (s.callbacks.on_open)
        s.callbacks.on_open(s.id);
    return true;
}
// A SYN on a synchronized session. True only when a retransmitted SYN+ACK completes a
// simultaneous open whose final ACK was lost; otherwise the segment is answered here.
bool TcpManager::repeated_syn(Key const &key, Session &s, TcpView const &tcp, std::uint64_t seq) {
    bool ack = tcp.has_flag(TcpFlag::Ack);
    if (s.state == State::SynReceived and not ack and seq + 1 == s.next) {
        send_control(key, s); // Retransmitted SYN: repeat our SYN+ACK.
        return false;
    }
    if (ack and tcp.acknowledgment_number() == s.iss + 1 and
        tcp.sequence_number() == s.peer_iss and not tcp.has_flag(TcpFlag::Fin) and
        s.state == State::SynReceived) {
        s.snd_una = s.snd_nxt;
        s.state = State::Established;
        if (s.callbacks.on_open)
            s.callbacks.on_open(s.id);
        return true;
    }
    send(key, s, 0x10, s.snd_nxt);
    return false;
}
// ACK field: advance the send window and the closing states. False when nothing remains to
// deliver (session finished, or the receive direction is already closed).
bool TcpManager::acknowledge(Iterator it, TcpView const &tcp, Clock::time_point now) {
    auto const &key = it->first;
    auto &s = it->second;
    s.peer_window = tcp.window();
    if (s.flight) {
        auto acknowledged = tcp.acknowledgment_number() - s.snd_una;
        if (acknowledged <= s.flight and acknowledged) {
            s.tx.erase(s.tx.begin(), s.tx.begin() + acknowledged);
            s.flight -= acknowledged;
            s.snd_una += acknowledged;
            s.retries = 0;
            s.deadline = now + std::chrono::seconds(1);
        }
    } else if (tcp.acknowledgment_number() == s.snd_nxt)
        s.snd_una = s.snd_nxt;
    s.activity = now;
    bool all_acked = s.snd_una == s.snd_nxt;
    if (s.state == State::LastAck and all_acked) {
        finish(it, false);
        return false;
    }
    if (s.state == State::Closing and all_acked) {
        enter_time_wait(s, now);
        if (tcp.has_flag(TcpFlag::Fin))
            send(key, s, 0x10, s.snd_nxt);
        return false;
    }
    if (s.state == State::FinWait1 and all_acked)
        s.state = State::FinWait2;
    if (s.state == State::LastAck or s.state == State::Closing or s.state == State::CloseWait) {
        if (tcp.has_flag(TcpFlag::Fin))
            send(key, s, 0x10, s.snd_nxt); // Peer retransmitted its FIN.
        return false;
    }
    return true;
}
// Payload and FIN: in-order bytes go straight to on_data, then one ACK (or a deferred one).
void TcpManager::deliver(Key const &key, Session &s, TcpView const &tcp, bool handshake,
                         Clock::time_point now) {
    auto const before = s.next;
    data(s, tcp);
    if (s.fin and *s.fin == s.next) {
        ++s.next;
        s.pending.clear();
        auto old = s.state;
        if (old == State::Established)
            s.state = State::CloseWait;
        if (s.callbacks.on_eof)
            s.callbacks.on_eof(s.id);
        if (old == State::Established) {
            // Upper layers may send TLS shutdown bytes after peer EOF.
            send(key, s, 0x10, s.snd_nxt);
            if (not s.callbacks.manual_close) {
                s.close_requested = true;
                pump_tx(key, s, now);
            }
        } else {
            if (old == State::FinWait2)
                enter_time_wait(s, now);
            else
                s.state = State::Closing;
            send(key, s, 0x10, s.snd_nxt);
        }
    } else if (batching_ and not handshake and not tcp.has_flag(TcpFlag::Fin) and
               s.next > before and s.pending.empty())
        s.ack_pending = true; // In-order progress: one cumulative ACK at end_batch.
    else if (handshake or tcp.payload().length or tcp.has_flag(TcpFlag::Fin))
        send(key, s, 0x10, s.snd_nxt);
}
void TcpManager::end_batch() {
    batching_ = false;
    for (auto const &[key, s] : sessions_)
        if (s.ack_pending)
            send(key, s, 0x10, s.snd_nxt);
}
void TcpManager::poll(Clock::time_point now) {
    for (auto it = sessions_.begin(); it != sessions_.end();) {
        auto &s = it->second;
        if (s.state == State::TimeWait) {
            if (now >= s.deadline) {
                auto done = it++;
                finish(done, false);
            } else
                ++it;
            continue;
        }
        pump_tx(it->first, s, now);
        bool expired = now - s.activity >= std::chrono::seconds(60);
        bool retry = s.flight != 0 or s.state == State::Resolving or s.state == State::SynSent or
                     s.state == State::SynReceived or s.state == State::FinWait1 or
                     s.state == State::Closing or s.state == State::LastAck;
        if (not expired and retry and now >= s.deadline) {
            if (s.retries >= 5)
                expired = true;
            else if (s.state == State::Resolving and resolve(it->first, s, now)) {
            } else {
                if (s.flight)
                    send(it->first, s, 0x18, s.snd_una, Bytes<>{s.tx}.first(s.flight));
                else if (s.state != State::Resolving)
                    send_control(it->first, s);
                s.deadline = now + std::chrono::seconds(1U << ++s.retries);
            }
        }
        if (expired) {
            auto done = it++;
            finish(done, true);
        } else
            ++it;
    }
}
} // namespace protocol
