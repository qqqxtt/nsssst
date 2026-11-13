#pragma once
#include "udp.hpp"
#include "receive_trace.hpp"
#include <functional>
#include <unordered_map>

namespace protocol {
// Called synchronously with an owned frame's borrowed bytes; must not retain the span.
using UdpFrameSender = std::function<bool(Bytes<>)>;
class UdpPortRegistry;
// Callback-scoped: do not retain this reference or the datagram's payload.
class UdpReplySender {
  public:
    UdpReplySender(UdpReplySender const &) = delete;
    UdpReplySender &operator=(UdpReplySender const &) = delete;
    UdpReplySender(UdpReplySender &&) = delete;
    UdpReplySender &operator=(UdpReplySender &&) = delete;
    [[nodiscard]] bool send(Bytes<> payload) const;
    [[nodiscard]] bool send(PacketSlice const &payload) const;

  private:
    friend class UdpPortRegistry;
    explicit UdpReplySender(UdpReplyInfo info, UdpFrameSender const &sender)
        : info_(info), sender_(sender) {}
    UdpReplyInfo info_;
    UdpFrameSender const &sender_;
};
using UdpHandler = std::function<void(UdpDatagramView const &, UdpReplySender const &)>;
enum class UdpDispatchResult { Invalid, Unregistered, Handled };

// Startup registration, then frozen single-threaded dispatch. Callback exceptions propagate.
class UdpPortRegistry {
  public:
    UdpPortRegistry() = default;
    UdpPortRegistry(UdpPortRegistry const &) = delete;
    UdpPortRegistry &operator=(UdpPortRegistry const &) = delete;
    UdpPortRegistry(UdpPortRegistry &&) = delete;
    UdpPortRegistry &operator=(UdpPortRegistry &&) = delete;
    void register_port(std::uint16_t port, UdpHandler handler);
    void freeze() noexcept { frozen_ = true; }
    [[nodiscard]] UdpDispatchResult dispatch(IPv4View const &ip, Bytes<6> local_mac,
                                             Bytes<6> peer_mac, UdpFrameSender const &sender, ReceiveTrace *trace = nullptr) const;

  private:
    std::unordered_map<std::uint16_t, UdpHandler> handlers_;
    bool frozen_{};
};
} // namespace protocol
