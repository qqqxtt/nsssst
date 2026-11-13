#include "tcp_manager.hpp"
#include "tcp_sequence.hpp"
#include <algorithm>
namespace protocol {
namespace {
constexpr std::uint32_t window = 32768;
}
void TcpManager::data(Session &s, TcpView const &tcp) {
    auto bytes = tcp.payload();
    auto start = unwrap(tcp.sequence_number(), s.next) + tcp.has_flag(TcpFlag::Syn);
    auto end = start + bytes.length;
    auto right = s.next + window;
    if (tcp.has_flag(TcpFlag::Fin) and end >= s.next and end < right and not s.fin)
        s.fin = end;
    end = std::min(end, right);
    if (s.fin)
        end = std::min(end, *s.fin);
    auto pos = std::max(start, s.next);
    // Existing bytes win. Deliver gaps from the current packet, queue only future gaps.
    while (pos < end) {
        auto it = std::find_if(s.pending.begin(), s.pending.end(),
                               [&](auto const &f) { return f.begin + f.data.length > pos; });
        if (it != s.pending.end() and it->begin <= pos) {
            pos = std::min(end, it->begin + it->data.length);
            continue;
        }
        auto stop = it == s.pending.end() ? end : std::min(end, it->begin);
        PacketSlice part{bytes.packet, bytes.offset + static_cast<std::uint32_t>(pos - start),
                         static_cast<std::uint32_t>(stop - pos)};
        if (pos == s.next) {
            if (s.callbacks.on_data) {
                trace_delivery(trace_);
                s.callbacks.on_data(s.id, part);
            }
            s.next = stop;
        } else if (s.pending.size() < 32 and retained_segments() + bytes.packet->nb_segs <= 2048) {
            s.pending.insert(
                it, Fragment{pos, {retain_packet(*bytes.packet), part.offset, part.length}});
        }
        pos = stop;
        while (not s.pending.empty() and s.pending.front().begin == s.next) {
            auto f = std::move(s.pending.front());
            s.pending.erase(s.pending.begin());
            auto view = f.data.view();
            if (s.fin and f.begin + view.length > *s.fin)
                view.length = *s.fin - f.begin;
            if (view.length and s.callbacks.on_data) {
                trace_delivery(trace_, true);
                s.callbacks.on_data(s.id, view);
            }
            s.next += view.length;
        }
        pos = std::max(pos, s.next); // Buffered delivery may overtake the current packet cursor.
    }
}
} // namespace protocol
