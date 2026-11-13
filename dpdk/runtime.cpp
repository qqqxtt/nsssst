#include "runtime.hpp"

#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <exception>
#include <stdexcept>
#include <system_error>
#include <algorithm>
#include <limits>

namespace {

void check(int result, char const *operation) {
    if (result < 0) {
        throw std::system_error(-result, std::generic_category(), operation);
    }
}

void report_cleanup(int result, char const *operation) noexcept {
    if (result < 0) {
        std::fprintf(stderr, "%s: %s (%d)\n", operation, std::strerror(-result), result);
    }
}

void check_cleanup(int result, char const *operation) noexcept {
    if (result < 0) {
        report_cleanup(result, operation);

        std::fputs("Cannot safely release port resources; terminating.\n", stderr);
        std::terminate();
    }
}

unsigned queue_socket(std::uint16_t port_id) noexcept {
    auto const socket = rte_eth_dev_socket_id(port_id);
    return socket < 0 ? rte_socket_id() : static_cast<unsigned>(socket);
}

} // namespace

namespace dpdk {

void PacketDeleter::operator()(rte_mbuf *packet) const noexcept {
    rte_pktmbuf_free(packet);
}

std::array<unsigned char, 6> mac_address(EthPort const &port) {
    rte_ether_addr mac{};
    check(rte_eth_macaddr_get(port.id(), &mac), "get port MAC");
    std::array<unsigned char, 6> result{};
    std::copy_n(mac.addr_bytes, 6, result.begin());
    return result;
}

TxQueue::~TxQueue() noexcept {
    try { flush(); }
    catch (...) { std::fputs("TX cleanup flush failed\n", stderr); }
    if (pending_.size())
        std::fprintf(stderr, "TX cleanup: %zu unsent packets released\n", pending_.size());
}

bool TxQueue::enqueue(std::span<unsigned char const> frame) {
    if (not port_.is_started()) throw std::logic_error("TX port is stopped");
    if (frame.empty() or frame.size() > std::numeric_limits<std::uint16_t>::max())
        throw std::invalid_argument("invalid TX frame length");
    if (pending_.full()) return false;
    Packet packet{rte_pktmbuf_alloc(&pool_)};
    if (not packet) return false;
    auto *data = rte_pktmbuf_append(packet.get(), static_cast<std::uint16_t>(frame.size()));
    if (data == nullptr) return false;
    std::memcpy(data, frame.data(), frame.size());
    return pending_.push(std::move(packet));
}
std::size_t TxQueue::flush() {
    if (not port_.is_started()) throw std::logic_error("TX port is stopped");
    return pending_.flush([this](std::span<rte_mbuf *> packets) {
        return rte_eth_tx_burst(port_.id(), 0, packets.data(), static_cast<std::uint16_t>(packets.size()));
    });
}

EAL::EAL(int argc, char **argv) {
    if (rte_eal_init(argc, argv) < 0) {
        throw std::system_error(rte_errno, std::generic_category(), "initialize EAL");
    }
}

EAL::~EAL() noexcept {
    report_cleanup(rte_eal_cleanup(), "clean up EAL");
}

void MempoolDeleter::operator()(rte_mempool *pool) const noexcept {
    rte_mempool_free(pool);
}

Mempool create_mempool() {
    Mempool pool{
        rte_pktmbuf_pool_create(
            "PACKET_POOL", 
            8191, 256, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 
            static_cast<int>(rte_socket_id())
        )
    };
    if (!pool) {
        throw std::system_error(rte_errno, std::generic_category(), "create packet mempool");
    }
    return pool;
}

EthPort::EthPort(std::uint16_t port_id) : port_id_(port_id) {
    if (!rte_eth_dev_is_valid_port(port_id_)) {
        throw std::runtime_error("requested Ethernet port does not exist");
    }
}

EthPort::~EthPort() noexcept {
    if (started_) {
        check_cleanup(rte_eth_dev_stop(port_id_), "stop Ethernet port");
    }
    check_cleanup(rte_eth_dev_close(port_id_), "close Ethernet port");
}

void EthPort::configure_queues(rte_mempool &pool) {
    rte_eth_dev_info info{};
    check(rte_eth_dev_info_get(port_id_, &info), "get Ethernet device info");
    rte_eth_conf config{};
    check(rte_eth_dev_configure(port_id_, 1, 1, &config), "configure port");

    std::uint16_t rx_desc = 1024;
    std::uint16_t tx_desc = 1024;
    check(rte_eth_dev_adjust_nb_rx_tx_desc(port_id_, &rx_desc, &tx_desc), "adjust descriptors");

    auto rx_conf = info.default_rxconf;
    rx_conf.offloads = config.rxmode.offloads;
    auto tx_conf = info.default_txconf;
    tx_conf.offloads = config.txmode.offloads;
    auto const socket = queue_socket(port_id_);
    check(rte_eth_rx_queue_setup(port_id_, 0, rx_desc, socket, &rx_conf, &pool),
          "set up RX queue");
    check(rte_eth_tx_queue_setup(port_id_, 0, tx_desc, socket, &tx_conf),
          "set up TX queue");
}

void EthPort::start(rte_mempool &pool) {
    if (started_) {
        throw std::logic_error("Ethernet port is already started");
    }
    configure_queues(pool);
    check(rte_eth_dev_start(port_id_), "start Ethernet port");
    started_ = true;
}

std::uint16_t EthPort::id() const noexcept {
    return port_id_;
}

bool EthPort::is_started() const noexcept {
    return started_;
}

RxBatch::RxBatch(EthPort const &port) {
    if (!port.is_started()) {
        throw std::logic_error("cannot receive from a stopped Ethernet port");
    }
    count_ = rte_eth_rx_burst(port.id(), 0, packets_.data(), CAPACITY);
}

RxBatch::~RxBatch() noexcept {
    if (count_ != 0) {
        rte_pktmbuf_free_bulk(packets_.data(), count_);
    }
}

std::span<rte_mbuf *const> RxBatch::packets() const noexcept {
    return {packets_.data(), count_};
}

SignalHandler::SignalHandler(int signal_number, void (*handler)(int))
    : signal_number_(signal_number) {
    struct sigaction action{};
    action.sa_handler = handler;
    if (sigemptyset(&action.sa_mask) < 0 || sigaction(signal_number_, &action, &previous_) < 0) {
        throw std::system_error(errno, std::generic_category(), "install signal handler");
    }
}

SignalHandler::~SignalHandler() noexcept {
    if (sigaction(signal_number_, &previous_, nullptr) < 0) {
        report_cleanup(-errno, "restore signal handler");
    }
}

} // namespace dpdk
