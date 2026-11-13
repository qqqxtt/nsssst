#pragma once
#include "address.hpp"
#include "packet_ref.hpp"
#include "receive_trace.hpp"
#include "tcp.hpp"
#include <chrono>
#include <functional>
#include <map>
#include <vector>
namespace protocol {
using TcpConnectionId = std::uint64_t;
struct TcpCallbacks {
    std::function<void(TcpConnectionId)> on_open;
    std::function<void(TcpConnectionId, PacketSlice)> on_data;
    std::function<void(TcpConnectionId)> on_eof;
    std::function<void(TcpConnectionId, bool)> on_closed; // true: reset/timeout
    bool manual_close{}; // Keep receive half-close open for TLS shutdown.
};
struct TcpConnectOptions {
    Ipv4Address peer;
    std::uint16_t local_port;
    std::uint16_t peer_port;
    std::optional<MacAddress> next_hop_mac; // Omit to resolve through the stack's ARP cache.
};
// Single thread. Callbacks synchronous, must not retain views or reenter the manager.
// EOF automatically initiates passive close unless callbacks.manual_close is set.
class TcpManager {
  public:
    using Clock = std::chrono::steady_clock;
    using Sender = std::function<bool(Bytes<>)>;
    using Resolver = std::function<std::optional<MacAddress>(Ipv4Address, Clock::time_point)>;
    TcpManager(LocalAddress local, Sender sender, Resolver resolver = {});
    [[nodiscard]] TcpConnectionId connect(
        TcpConnectOptions options, TcpCallbacks callbacks, Clock::time_point now);
    // Copies accepted bytes into a bounded queue; acceptance is not peer acknowledgement.
    std::size_t write(TcpConnectionId id, Bytes<> bytes);
    bool flushed(TcpConnectionId id) const;
    bool closed(TcpConnectionId id) const;
    void detach(TcpConnectionId id);
    void abort(TcpConnectionId id) noexcept;
    [[nodiscard]] bool close(TcpConnectionId id, Clock::time_point now);
    TcpManager(TcpManager const&) = delete;
    TcpManager& operator=(TcpManager const&) = delete;
    TcpManager(TcpManager&&) = delete;
    TcpManager& operator=(TcpManager&&) = delete;
    void listen(std::uint16_t port, TcpCallbacks callbacks);
    void receive(IPv4View const& ip, TcpView const& tcp, Bytes<6> peer_mac, Clock::time_point now,
        ReceiveTrace* trace = nullptr);
    void poll(Clock::time_point now);
    // Between begin_batch and end_batch, pure ACKs for in-order data are coalesced:
    // each session sends at most one cumulative ACK when the batch ends, unless a
    // segment carrying ACK was sent earlier. Handshake, FIN and error ACKs stay immediate.
    void begin_batch() noexcept { batching_ = true; }
    void end_batch();
    std::size_t size() const { return sessions_.size(); }

  private:
    enum class State {
        Resolving,
        SynSent,
        SynReceived,
        Established,
        CloseWait,
        FinWait1,
        FinWait2,
        Closing,
        LastAck,
        TimeWait
    };
    struct Key {
        Ipv4Address peer;
        std::uint16_t local_port, peer_port;
        auto operator<=>(Key const&) const = default;
    };
    struct Fragment {
        std::uint64_t begin;
        RetainedSlice data;
    };
    struct Session {
        TcpConnectionId id;
        State state{State::SynReceived};
        MacAddress mac;
        std::uint32_t iss, snd_una, snd_nxt, peer_iss;
        std::uint64_t next; // unwrapped receive position, starts above 2^32
        std::optional<std::uint64_t> fin;
        std::vector<Fragment> pending;
        Clock::time_point deadline, activity;
        unsigned retries{};
        TcpCallbacks callbacks;
        std::vector<unsigned char> tx;
        std::size_t flight{};
        std::uint16_t peer_window{32768};
        bool close_requested{};
        std::uint16_t mss{536};
        mutable bool ack_pending{}; // Cleared by any sent segment carrying ACK.
    };
    using Iterator = std::map<Key, Session>::iterator;
    using ConstIterator = std::map<Key, Session>::const_iterator;
    Iterator find(TcpConnectionId id);
    ConstIterator find(TcpConnectionId id) const;
    void accept(Key const&, TcpView const&, Bytes<6> mac, Clock::time_point);
    bool syn_sent(Iterator, TcpView const&, Clock::time_point);
    bool repeated_syn(Key const&, Session&, TcpView const&, std::uint64_t seq);
    bool acknowledge(Iterator, TcpView const&, Clock::time_point);
    void deliver(Key const&, Session&, TcpView const&, bool handshake, Clock::time_point);
    void send(
        Key const&, Session const&, std::uint8_t flags, std::uint32_t seq, Bytes<> payload = {});
    void pump_tx(Key const&, Session&, Clock::time_point);
    void data(Session&, TcpView const&);
    void enter_time_wait(Session&, Clock::time_point);
    void send_control(Key const&, Session const&);
    void finish(Iterator, bool error);
    bool resolve(Key const&, Session&, Clock::time_point);
    ReceiveTrace* trace_{};
    bool batching_{};
    LocalAddress local_;
    Sender sender_;
    Resolver resolver_;
    std::map<std::uint16_t, TcpCallbacks> listeners_;
    std::map<Key, Session> sessions_;
    TcpConnectionId next_id_{1};
    std::uint32_t next_iss_;
    std::size_t retained_segments() const;
};
} // namespace protocol
