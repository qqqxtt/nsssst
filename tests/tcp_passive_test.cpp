#include "tcp_fixture.hpp"
int main() {
    auto now = TcpManager::Clock::time_point{};
    std::vector<std::vector<unsigned char>> sent;
    unsigned opens{}, eofs{}, closes{}, errors{};
    std::string output;
    TcpManager m({{2, 0, 0, 0, 0, 2}, {192, 0, 2, 2}}, [&](Bytes<> b) {
        sent.emplace_back(b.begin(), b.end());
        return true;
    });
    m.listen(19000, {[&](auto) { ++opens; },
                     [&](auto, PacketSlice s) {
                         check(for_each_chunk(s, [&](Bytes<> b) {
                             output.append(reinterpret_cast<char const *>(b.data()), b.size());
                         }));
                     },
                     [&](auto) { ++eofs; },
                     [&](auto, bool error) {
                         ++closes;
                         errors += error;
                     }});
    Input syn(0xfffffffe, 0, 2);
    syn.deliver(m, now);
    check(m.size() == 1 and sent.size() == 1);
    auto response = [&] { return sent_segment(sent.back()); };
    auto iss = response().sequence_number();
    check(response().acknowledgment_number() == 0xffffffff);
    syn.deliver(m, now);
    check(sent.size() == 2 and response().sequence_number() == iss);
    Input ack(0xffffffff, iss + 1, 16);
    ack.deliver(m, now);
    check(opens == 1);
    Input later(2, iss + 1, 16, "def");
    ReceiveTrace later_trace{};
    later.deliver(m, now, &later_trace);
    check(later_trace.callbacks == 0 && later_trace.buffered_callbacks == 0);
    check(output.empty() and rte_mbuf_refcnt_read(&later.head) == 2 and
          rte_mbuf_refcnt_read(&later.tail) == 2);
    Input fin(5, iss + 1, 17);
    fin.deliver(m, now);
    check(eofs == 0);
    Input overlap(1, iss + 1, 16, "cXX");
    ReceiveTrace overlap_trace{};
    overlap.deliver(m, now, &overlap_trace);
    Input first(0xffffffff, iss + 1, 16, "ab");
    ReceiveTrace first_trace{};
    first.deliver(m, now, &first_trace);
    check(first_trace.connection_id != 0);
    check(first_trace.callbacks == 1 && first_trace.delivery_ns != 0 && first_trace.buffered_callbacks >= 1);
    check(output == "abcdef" and eofs == 1);
    check(rte_mbuf_refcnt_read(&later.head) == 1 and rte_mbuf_refcnt_read(&later.tail) == 1);
    check(rte_mbuf_refcnt_read(&overlap.head) == 1);
    check(response().flags() == 17 and response().acknowledgment_number() == 6);
    m.poll(now + std::chrono::seconds(1));
    check(response().sequence_number() == iss + 1);
    Input final_ack(6, iss + 2, 16);
    final_ack.deliver(m, now);
    check(m.size() == 0 and closes == 1 and errors == 0);
    // Handshake data and reset cleanup of an out-of-order chain.
    Input syn2(100, 0, 2);
    syn2.deliver(m, now);
    iss = response().sequence_number();
    Input third(101, iss + 1, 16, "x");
    third.deliver(m, now);
    check(output == "abcdefx");
    Input pending(105, iss + 1, 16, "z");
    pending.deliver(m, now);
    check(rte_mbuf_refcnt_read(&pending.tail) == 2);
    Input bad_rst(104, 0, 4);
    bad_rst.deliver(m, now);
    check(m.size() == 1);
    Input rst(102, 0, 4);
    rst.deliver(m, now);
    check(m.size() == 0 and errors == 1 and rte_mbuf_refcnt_read(&pending.tail) == 1);
    syn2.deliver(m, now);
    m.poll(now + std::chrono::seconds(61));
    check(m.size() == 0 and errors == 2);
    // Bound the queue and still allow an in-order packet to fill every gap.
    syn2.deliver(m, now);
    iss = response().sequence_number();
    Input establish(101, iss + 1, 16);
    establish.deliver(m, now);
    std::vector<std::unique_ptr<Input>> queued;
    for (unsigned i = 0; i < 33; ++i) {
        queued.push_back(std::make_unique<Input>(103 + i * 2, iss + 1, 16, "Q"));
        queued.back()->deliver(m, now);
        check(rte_mbuf_refcnt_read(&queued.back()->head) == (i < 32 ? 2 : 1));
    }
    auto before = output.size();
    Input fill(101, iss + 1, 16, std::string(70, 'a'));
    ReceiveTrace fill_trace{.begin_ns=receive_clock_ns()};
    fill.deliver(m, now, &fill_trace);
    check(fill_trace.callbacks > 1 && fill_trace.buffered_callbacks > 1);
    check(fill_trace.delivery_ns >= fill_trace.begin_ns);
    check(output.size() == before + 70);
    for (unsigned i = 0; i < 70; ++i)
        check(output[before + i] == (i >= 2 and i <= 64 and i % 2 == 0 ? 'Q' : 'a'));
    for (auto const &q : queued)
        check(rte_mbuf_refcnt_read(&q->head) == 1);
    Input cleanup(171, 0, 4);
    cleanup.deliver(m, now);
    check(m.size() == 0);
    std::puts(
        "PASS: TCP handshake, wrapping overlap reassembly, FIN, RST, timers, chained references");
}
