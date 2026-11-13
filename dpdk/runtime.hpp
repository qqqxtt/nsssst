#pragma once

#include <rte_mbuf.h>
#include "pending_tx.hpp"

#include <array>
#include <cstdint>
#include <memory>
#include <signal.h>
#include <span>

namespace dpdk {

class EAL {
public:
    EAL(int argc, char **argv);
    ~EAL() noexcept;

    EAL(EAL const &) = delete;
    EAL &operator=(EAL const &) = delete;
    EAL(EAL &&) = delete;
    EAL &operator=(EAL &&) = delete;
};

struct MempoolDeleter {
    void operator()(rte_mempool *pool) const noexcept;
};

using Mempool = std::unique_ptr<rte_mempool, MempoolDeleter>;

[[nodiscard]] Mempool create_mempool();

struct PacketDeleter {
    void operator()(rte_mbuf *packet) const noexcept;
};
using Packet = std::unique_ptr<rte_mbuf, PacketDeleter>;


class EthPort {
public:
    explicit EthPort(std::uint16_t port_id);
    ~EthPort() noexcept;

    EthPort(EthPort const &) = delete;
    EthPort &operator=(EthPort const &) = delete;
    EthPort(EthPort &&) = delete;
    EthPort &operator=(EthPort &&) = delete;

    void start(rte_mempool &pool);
    [[nodiscard]] std::uint16_t id() const noexcept;
    [[nodiscard]] bool is_started() const noexcept;

private:
    void configure_queues(rte_mempool &pool);

    std::uint16_t port_id_;
    bool started_{};
};


// Single-threaded bounded TX ownership. Port/pool must outlive this queue.
class TxQueue {
  public:
    TxQueue(EthPort const &port, rte_mempool &pool) : port_(port), pool_(pool) {}
    ~TxQueue() noexcept;
    // True means queued, not yet handed to PMD. Full queues never flush implicitly.
    [[nodiscard]] bool enqueue(std::span<unsigned char const> frame);
    // One attempt; the unsent suffix remains owned for the next iteration.
    std::size_t flush();
    std::size_t size() const noexcept { return pending_.size(); }
  private:
    EthPort const &port_;
    rte_mempool &pool_;
    PendingTx<Packet,64> pending_;
};

[[nodiscard]] std::array<unsigned char, 6> mac_address(EthPort const &port);

class RxBatch {
public:
    explicit RxBatch(EthPort const &port);
    ~RxBatch() noexcept;

    RxBatch(RxBatch const &) = delete;
    RxBatch &operator=(RxBatch const &) = delete;
    RxBatch(RxBatch &&) = delete;
    RxBatch &operator=(RxBatch &&) = delete;

    [[nodiscard]] std::span<rte_mbuf *const> packets() const noexcept;

private:
    static constexpr std::uint16_t CAPACITY = 32;
    std::array<rte_mbuf *, CAPACITY> packets_{};
    std::uint16_t count_{};
};


class SignalHandler {
public:
    SignalHandler(int signal_number, void (*handler)(int));
    ~SignalHandler() noexcept;

    SignalHandler(SignalHandler const &) = delete;
    SignalHandler &operator=(SignalHandler const &) = delete;
    SignalHandler(SignalHandler &&) = delete;
    SignalHandler &operator=(SignalHandler &&) = delete;

private:
    int signal_number_;
    struct sigaction previous_{};
};

} // namespace dpdk
