#include "tcp.hpp"
#include "checksum.hpp"
#include <algorithm>

namespace protocol {
namespace {
bool valid_options(Bytes<> bytes) {
    for (std::size_t offset = 0; offset < bytes.size();) {
        auto kind = bytes[offset];
        if (kind == 0) // EOL: the remaining bytes are padding.
            return true;
        if (kind == 1) { // NOP has no length byte.
            ++offset;
            continue;
        }
        if (bytes.size() - offset < 2)
            return false;
        auto length = bytes[offset + 1];
        if (length < 2 or length > bytes.size() - offset)
            return false;
        // Structural checks for the common fixed-format options. Unknown kinds are skipped.
        if ((kind == 2 and length != 4) or (kind == 3 and length != 3) or
            (kind == 4 and length != 2) or (kind == 5 and (length < 10 or (length - 2) % 8 != 0)) or
            (kind == 8 and length != 10))
            return false;
        offset += length;
    }
    return true;
}
} // namespace

std::optional<TcpView> TcpView::parse(IPv4View const& ip) {
    auto message = ip.payload();
    if (ip.protocol() != IP_PROTOCOL_TCP or message.length < TCP_HEADER_LENGTH)
        return std::nullopt;
    // One read covers the largest possible header; the data offset is checked afterwards.
    std::array<unsigned char, TCP_MAX_HEADER_LENGTH> snapshot{};
    auto const available = std::min(message.length, TCP_MAX_HEADER_LENGTH);
    auto const* header = static_cast<unsigned char const*>(
        rte_pktmbuf_read(message.packet, message.offset, available, snapshot.data()));
    if (header == nullptr)
        return std::nullopt;
    auto length = static_cast<std::uint32_t>((header[12] >> 4) * 4);
    if (length < TCP_HEADER_LENGTH or length > message.length)
        return std::nullopt;
    // rte_pktmbuf_read may return packet memory directly, so always keep our own snapshot.
    if (header != snapshot.data())
        std::copy_n(header, length, snapshot.begin());
    if (not valid_options(Bytes<>{snapshot}.subspan(TCP_HEADER_LENGTH, length - TCP_HEADER_LENGTH)))
        return std::nullopt;

    std::array<unsigned char, 12> pseudo{};
    std::copy(ip.source().begin(), ip.source().end(), pseudo.begin());
    std::copy(ip.destination().begin(), ip.destination().end(), pseudo.begin() + 4);
    pseudo[9] = IP_PROTOCOL_TCP;
    pseudo[10] = static_cast<unsigned char>(message.length >> 8);
    pseudo[11] = static_cast<unsigned char>(message.length & 255);
    InternetChecksum checksum;
    checksum.add(pseudo);
    if (not for_each_chunk(message, [&](Bytes<> chunk) { checksum.add(chunk); }) or
        checksum.value() != 0)
        return std::nullopt;
    return TcpView{snapshot, {message.packet, message.offset + length, message.length - length}};
}
} // namespace protocol
