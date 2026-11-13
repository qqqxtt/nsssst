#include "tcp_fixture.hpp"
int main() {
    auto now = TcpManager::Clock::time_point{};
    std::vector<std::vector<unsigned char>> frames;
    TcpManager m({{2, 0, 0, 0, 0, 2}, {192, 0, 2, 2}}, [&](Bytes<> b) {
        frames.emplace_back(b.begin(), b.end());
        return true;
    });
    auto response = [&] { return sent_segment(frames.back()); };
    auto id = m.connect({{192, 0, 2, 1}, 19000, 12345, MacAddress{2, 0, 0, 0, 0, 1}},
                        {.on_data = [](auto, PacketSlice) {}}, now);
    auto iss = response().sequence_number();
    Input handshake(100, iss + 1, 18);
    handshake.deliver(m, now);
    std::vector<unsigned char> bytes(70000, 42);
    check(m.write(id, bytes) == 65536);
    check(m.write(id, bytes) == 0);
    m.poll(now);
    check(response().payload().length == 536);
    auto first = frames.back();
    m.poll(now + std::chrono::seconds(1));
    check(frames.back() == first);
    Input partial(101, iss + 101, 16);
    partial.deliver(m, now);
    m.poll(now + std::chrono::seconds(2));
    check(response().sequence_number() == iss + 101 and response().payload().length == 436);
    Input zero(101, iss + 537, 16, "", 0);
    zero.deliver(m, now);
    m.poll(now + std::chrono::seconds(3));
    check(response().payload().length == 0); // zero-window probe instead of new data
    Input reopen(101, iss + 537, 16, "", 5);
    reopen.deliver(m, now);
    m.poll(now + std::chrono::seconds(3));
    check(response().payload().length == 5);
    check(m.close(id, now));
    check(m.write(id, bytes) == 0);
    check((response().flags() & 1) == 0); // FIN cannot overtake queued data.
    std::puts("PASS: TCP bounded writes, payload checksum, partial ACK, retransmission, zero "
              "window and deferred FIN");
}
