// ACK coalescing: in-order data inside one RX burst gets a single cumulative ACK at
// end_batch; out-of-order data still gets an immediate duplicate ACK.
#include "tcp_fixture.hpp"
int main() {
    auto now = TcpManager::Clock::time_point{};
    std::vector<std::vector<unsigned char>> sent;
    std::string output;
    TcpManager m({{2, 0, 0, 0, 0, 2}, {192, 0, 2, 2}}, [&](Bytes<> b) {
        sent.emplace_back(b.begin(), b.end());
        return true;
    });
    m.listen(19000, {.on_data = [&](auto, PacketSlice s) {
        check(for_each_chunk(s, [&](Bytes<> b) {
            output.append(reinterpret_cast<char const *>(b.data()), b.size());
        }));
    }});
    auto last = [&] { return sent_segment(sent.back()); };
    Input syn(1000, 0, 2);
    syn.deliver(m, now);
    auto iss = last().sequence_number();
    Input ack(1001, iss + 1, 16);
    ack.deliver(m, now);
    auto before = sent.size();

    // Three in-order segments in one burst: no ACK until end_batch, then exactly one.
    m.begin_batch();
    Input a(1001, iss + 1, 16, "abc"), b(1004, iss + 1, 16, "de"), c(1006, iss + 1, 16, "f");
    a.deliver(m, now);
    b.deliver(m, now);
    c.deliver(m, now);
    check(output == "abcdef" and sent.size() == before);
    m.end_batch();
    check(sent.size() == before + 1);
    check(last().flags() == 0x10 and last().acknowledgment_number() == 1007);
    m.end_batch(); // Nothing pending: no extra ACK.
    check(sent.size() == before + 1);

    // A gap inside a burst still produces an immediate duplicate ACK.
    m.begin_batch();
    Input future(1010, iss + 1, 16, "zz");
    future.deliver(m, now);
    check(sent.size() == before + 2 and last().acknowledgment_number() == 1007);
    Input fill(1007, iss + 1, 16, "ghi");
    fill.deliver(m, now); // Fills the gap and releases the buffered bytes in order.
    check(output == "abcdefghizz");
    m.end_batch();
    check(last().acknowledgment_number() == 1012);

    // Outside a batch every data segment is acknowledged immediately, as before.
    auto n = sent.size();
    Input d(1012, iss + 1, 16, "x");
    d.deliver(m, now);
    check(sent.size() == n + 1 and last().acknowledgment_number() == 1013);
    std::puts("PASS: TCP ACK batching");
}
