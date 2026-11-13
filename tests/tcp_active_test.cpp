#include "tcp_fixture.hpp"
int main() {
    using Clock = TcpManager::Clock;
    auto now = Clock::time_point{};
    std::vector<std::vector<unsigned char>> sent;
    unsigned opens{}, eofs{}, closes{}, errors{};
    std::string data;
    bool resolved = false;
    unsigned resolutions{};
    TcpManager manager(
        {{2, 0, 0, 0, 0, 2}, {192, 0, 2, 2}},
        [&](Bytes<> bytes) {
            sent.emplace_back(bytes.begin(), bytes.end());
            return true;
        },
        [&](Ipv4Address, Clock::time_point) -> std::optional<MacAddress> {
            ++resolutions;
            if (resolved)
                return MacAddress{2, 0, 0, 0, 0, 1};
            return {};
        });
    TcpCallbacks callbacks{[&](auto) { ++opens; },
                           [&](auto, PacketSlice bytes) {
                               check(for_each_chunk(bytes, [&](auto b) {
                                   data.append(reinterpret_cast<char const *>(b.data()), b.size());
                               }));
                           },
                           [&](auto) { ++eofs; },
                           [&](auto, bool error) {
                               ++closes;
                               errors += error;
                           }};
    TcpConnectOptions options{{192, 0, 2, 1}, 19000, 12345, {}};
    auto response = [&] { return sent_segment(sent.back()); };
    auto id = manager.connect(options, callbacks, now);
    check(resolutions == 1 and sent.empty());
    resolved = true;
    manager.poll(now + std::chrono::seconds(1));
    check(response().flags() == 2 and response().acknowledgment_number() == 0);
    auto iss = response().sequence_number();
    manager.poll(now + std::chrono::seconds(2));
    check(response().sequence_number() == iss and sent.size() == 2);
    Input bogus(200, iss + 2, 18);
    bogus.deliver(manager, now);
    check(opens == 0);
    Input synack(0xffffffff, iss + 1, 18, "hi");
    synack.deliver(manager, now);
    check(opens == 1 and data == "hi" and response().flags() == 16 and
          response().acknowledgment_number() == 2);
    synack.deliver(manager, now);
    check(opens == 1 and data == "hi");
    check(manager.close(id, now));
    check(response().flags() == 17 and response().sequence_number() == iss + 1);
    check(not manager.close(id, now));
    Input finack(2, iss + 2, 17);
    finack.deliver(manager, now);
    check(eofs == 1 and response().flags() == 16 and response().acknowledgment_number() == 3);
    // TIME_WAIT ignores RST and answers retransmitted FIN; reset its 2MSL timer.
    Input rst(3, 0, 4);
    rst.deliver(manager, now);
    check(manager.size() == 1);
    finack.deliver(manager, now + std::chrono::seconds(10));
    check(eofs == 1);
    manager.poll(now + std::chrono::seconds(129));
    check(manager.size() == 1);
    manager.poll(now + std::chrono::seconds(130));
    check(manager.size() == 0 and closes == 1 and errors == 0);
    // Simultaneous close: peer FIN does not acknowledge our FIN yet.
    options.next_hop_mac = MacAddress{2, 0, 0, 0, 0, 1};
    id = manager.connect(options, callbacks, now);
    iss = response().sequence_number();
    Input hello(100, iss + 1, 18);
    hello.deliver(manager, now);
    check(manager.close(id, now));
    Input early_fin(101, iss + 1, 17);
    early_fin.deliver(manager, now);
    check(response().flags() == 16);
    manager.poll(now + std::chrono::seconds(1));
    check(response().flags() == 17);
    Input done(102, iss + 2, 16);
    done.deliver(manager, now);
    manager.poll(now + std::chrono::seconds(120));
    check(manager.size() == 0 and errors == 0);
    // FIN_WAIT_2 continues delivering peer data after our FIN is acknowledged.
    id = manager.connect(options, callbacks, now);
    iss = response().sequence_number();
    Input h2(200, iss + 1, 18);
    h2.deliver(manager, now);
    check(manager.close(id, now));
    Input ack(201, iss + 2, 16);
    ack.deliver(manager, now);
    auto count = sent.size();
    manager.poll(now + std::chrono::seconds(1));
    check(sent.size() == count);
    Input text(201, iss + 2, 16, "bye");
    text.deliver(manager, now);
    check(data == "hibye");
    Input end(204, iss + 2, 17);
    end.deliver(manager, now);
    manager.poll(now + std::chrono::seconds(120));
    check(manager.size() == 0);
    // Refusal is accepted only when RST acknowledges the outstanding SYN.
    id = manager.connect(options, callbacks, now);
    iss = response().sequence_number();
    Input bad_reset(0, iss, 20);
    bad_reset.deliver(manager, now);
    check(manager.size() == 1);
    Input refusal(0, iss + 1, 20);
    refusal.deliver(manager, now);
    check(manager.size() == 0 and errors == 1);
    // Missing ARP and missing SYN+ACK both expire and report an error.
    options.next_hop_mac.reset();
    resolved = false;
    id = manager.connect(options, callbacks, now);
    manager.poll(now + std::chrono::seconds(61));
    check(manager.size() == 0 and errors == 2);
    options.next_hop_mac = MacAddress{2, 0, 0, 0, 0, 1};
    id = manager.connect(options, callbacks, now);
    manager.poll(now + std::chrono::seconds(61));
    check(manager.size() == 0 and errors == 3);
    // Simultaneous open: a bare SYN is answered using our original ISS.
    id = manager.connect(options, callbacks, now);
    iss = response().sequence_number();
    Input peer_syn(300, 0, 2);
    peer_syn.deliver(manager, now);
    check(response().flags() == 18 and response().sequence_number() == iss);
    auto previous_opens = opens;
    Input peer_synack(300, iss + 1, 18);
    peer_synack.deliver(manager, now);
    check(opens == previous_opens + 1 and response().flags() == 16);
    Input reset_established(301, 0, 4);
    reset_established.deliver(manager, now);
    check(manager.size() == 0);
    std::puts("PASS: TCP active ARP/SYN, retries, refusal, payload, close, simultaneous close and "
              "TIME_WAIT");
}
