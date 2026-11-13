#include "packet_ref.hpp"
#include <cstdio>
#include <rte_eal.h>
#include <rte_mempool.h>
#include <sched.h>
#include <stdexcept>
#include <string>
#include <vector>
using namespace protocol;
void check(bool b) {
    if (not b)
        throw std::runtime_error("packet reference test failed");
}
int main() {
    cpu_set_t cpus;
    CPU_ZERO(&cpus);
    check(sched_getaffinity(0, sizeof(cpus), &cpus) == 0);
    int cpu = 0;
    while (cpu < CPU_SETSIZE and not CPU_ISSET(cpu, &cpus))
        ++cpu;
    check(cpu < CPU_SETSIZE);
    std::vector<std::string> options{
        "packet_ref_test", "--lcores",       "0@" + std::to_string(cpu), "--no-pci", "--no-huge",
        "--no-shconf",     "--no-telemetry", "--log-level=error",        "-m",       "32"};
    std::vector<char *> args;
    for (auto &s : options)
        args.push_back(s.data());
    check(rte_eal_init(args.size(), args.data()) >= 0);
    struct EalCleanup {
        ~EalCleanup() { rte_eal_cleanup(); }
    } cleanup;
    auto deleter = [](rte_mempool *p) { rte_mempool_free(p); };
    std::unique_ptr<rte_mempool, decltype(deleter)> pool{
        rte_pktmbuf_pool_create("private_reference_test", 127, 0, 0, 512, SOCKET_ID_ANY), deleter};
    check(bool(pool));
    PacketRef original{rte_pktmbuf_alloc(pool.get())}, tail{rte_pktmbuf_alloc(pool.get())};
    check(bool(original) and bool(tail));
    auto *a = rte_pktmbuf_append(original.get(), 3);
    auto *b = rte_pktmbuf_append(tail.get(), 3);
    check(a and b);
    std::copy_n("abc", 3, a);
    std::copy_n("def", 3, b);
    check(rte_pktmbuf_chain(original.get(), tail.get()) == 0);
    tail.release();
    RetainedSlice held{retain_packet(*original), 1, 4};
    check(rte_mbuf_refcnt_read(original.get()) == 2 and rte_mbuf_refcnt_read(original->next) == 2);
    original.reset(); // Equivalent to RX releasing its ownership at batch end.
    check(rte_mempool_avail_count(pool.get()) == 125);
    std::string text;
    check(for_each_chunk(held.view(), [&](Bytes<> chunk) {
        text.append(reinterpret_cast<char const *>(chunk.data()), chunk.size());
    }));
    check(text == "bcde");
    held.owner.reset();
    check(rte_mempool_avail_count(pool.get()) == 127);
    std::puts("PASS: real chained mbufs survive original release and return to private mempool");
}
