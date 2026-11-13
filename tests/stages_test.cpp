#include "bench/stages.hpp"
#include "protocol/stack.hpp"
#include "protocol/udp_registry.hpp"
#include <stdexcept>
// packet_to_tcp semantics: the stack timestamps only the first direct delivery of a packet;
// releases from the out-of-order buffer are counted separately and never timestamped.
void receive_trace() {
    using namespace protocol;
    auto check = [](bool ok) {
        if (!ok)
            throw std::runtime_error("receive trace invariant");
    };
    ReceiveTrace a{}, b{};
    ReceiveTrace *slot = &a;
    try {
        ReceiveTraceScope scope{slot, &b};
        check(slot == &b);
        throw 1;
    } catch (int) {
    }
    check(slot == &a); // Restored even when a callback throws.
    LocalAddress local{{2, 0, 0, 0, 0, 2}, {192, 0, 2, 2}}, peer{{2, 0, 0, 0, 0, 1}, {192, 0, 2, 1}};
    unsigned calls{};
    ReceiveTrace trace{};
    UdpPortRegistry ports;
    ports.register_port(19000, [&](auto const &d, auto const &) {
        ++calls;
        check(d.payload.length == 64);
        if (calls == 1)
            check(trace.callbacks == 1 && trace.delivery_ns >= trace.begin_ns);
    });
    ports.freeze();
    Stack stack{{local, {}, 24, true}, ports, [](Bytes<>) { return true; }};
    stack.start();
    std::vector<unsigned char> payload(64, 0x5a);
    auto frame =
        *build_udp_reply({{peer.ip, 12345}, {local.ip, 19000}, peer.mac, local.mac}, payload);
    rte_mbuf packet{};
    packet.buf_addr = frame.data();
    packet.data_len = frame.size();
    packet.pkt_len = frame.size();
    packet.nb_segs = 1;
    trace.begin_ns = receive_clock_ns();
    trace.bytes = frame.size();
    stack.receive(packet, &trace);
    check(trace.transport == 17 && trace.callbacks == 1 && trace.delivery_ns >= trace.begin_ns);
    stack.receive(packet); // A previous stack-scoped trace must not be reused.
    check(calls == 2 && trace.callbacks == 1);
    ReceiveTrace buffered{};
    trace_delivery(&buffered, true);
    check(buffered.callbacks == 0 && buffered.delivery_ns == 0 && buffered.buffered_callbacks == 1);
    trace_delivery(&buffered);
    auto first = buffered.delivery_ns;
    trace_delivery(&buffered);
    check(buffered.callbacks == 2 && buffered.delivery_ns == first);
}
int main(int argc, char **argv) {
    receive_trace();
    auto check = [](bool ok) {
        if (!ok)
            throw std::runtime_error("stages invariant");
    };
    bench::StageSamples samples{2, 1};
    for (auto stage : {bench::Stage::PacketToTcp, bench::Stage::Tls, bench::Stage::Json}) {
        samples.record(stage, 100, 120, 9, 7); // independent warmup
        samples.record(stage, 100, 130, 10, 7);
        samples.record(stage, 100, 140, 11, 8);
        samples.record(stage, 100, 150, 12, 8);
        samples.record(stage, 200, 100, 1, 7); // invalid time must not wrap
        auto values = samples.samples(stage);
        check(values.size() == 2 && values[0].elapsed_ns == 30 && values[1].elapsed_ns == 40);
        check(values[0].gap_ns == 0 && values[1].gap_ns == 0); // all begins equal 100
        check(values[0].bytes == 10 && values[1].connection_id == 8 &&
              samples.overflow(stage) == 1);
    }
    if (argc == 2)
        samples.report(argv[1]);
    bench::StageSamples only{2,0,true};
    only.record(bench::Stage::PacketToTcp,1,3,110,7);
    only.record(bench::Stage::Tls,1,3,110,7);
    check(only.samples(bench::Stage::Tls).empty() && only.samples(bench::Stage::PacketToTcp).size()==1);
    if(argc==3) only.report(argv[2]);
    bench::StageSamples packets{8, 0, true};
    protocol::ReceiveTrace trace{.begin_ns=100, .delivery_ns=140, .bytes=164,
        .callbacks=3, .buffered_callbacks=2, .transport=6, .connection_id=7};
    packets.record_packet(trace); // Multiple direct/buffered callbacks still give one sample.
    auto packet = packets.samples(bench::Stage::PacketToTcp);
    check(packet.size()==1 && packet[0].elapsed_ns==40 && packet[0].bytes==164);
    trace.callbacks=0; // Out-of-order-only release or an ACK must not become a sample.
    packets.record_packet(trace);
    trace.callbacks=1; trace.transport=17;
    packets.record_packet(trace);
    check(packets.samples(bench::Stage::PacketToTcp).size()==1);
    bench::StageSamples gaps{4, 0, true};
    gaps.record(bench::Stage::PacketToTcp, 1000, 1100, 1, 1);
    gaps.record(bench::Stage::PacketToTcp, 5000, 5100, 1, 1);
    gaps.record(bench::Stage::PacketToTcp, 200000, 200100, 1, 1);
    auto g = gaps.samples(bench::Stage::PacketToTcp);
    check(g[0].gap_ns == 0 && g[1].gap_ns == 4000 && g[2].gap_ns == 195000);
    bench::StageSamples empty{0, 0};
    empty.record(bench::Stage::Tls, 1, 2, 1, 1);
    check(empty.samples(bench::Stage::Tls).empty() && empty.overflow(bench::Stage::Tls) == 1);
}
