#include "binance/book_ticker.hpp"
#include "client.hpp"
#include <algorithm>
#include <cstdio>
#include <deque>
#include <openssl/err.h>
#include <stdexcept>
using namespace protocol;
void check(bool b) {
    if (not b)
        throw std::runtime_error("WSS integration failure");
}
// How the in-memory test server behaves in one ctest case (tests/run_wss_test.py --mode NAME).
struct Mode {
    std::string_view name;
    unsigned quotes = 0;            // >0: send BookTicker quotes, then a WS close; 0: echo mode
    std::size_t echo_bytes = 9;     // echo mode: client message size ("hello WSS")
    bool fragment_quotes = false;   // split each quote into two frames with a ping in between
    bool fragment_echo = false;     // echo in two frames with a ping in between
    bool mask_echo = false;         // set the mask bit on server frames (client must reject)
    bool bad_accept = false;        // corrupt Sec-WebSocket-Accept (client must reject)
    std::size_t write_chunk = 0;    // bytes per SSL_write; 0 writes everything at once
    bool write_until_empty = false; // with write_chunk: drain tx in one iteration
    bool tls12 = false;             // cap the server at TLS 1.2
    bool direct_tls = true;         // client option
    bool key_update = false;        // server KeyUpdate(update_requested) after quotes 1-2
    int expect_direct = -1;         // 1: direct TLS must be active, 0: must not, -1: either
};
// Modes that deliver everything in one burst finish before an idle record boundary, so direct
// TLS may or may not engage there.
constexpr Mode modes[] = {
    {.name = "", .expect_direct = 1},
    {.name = "fragment", .fragment_echo = true, .expect_direct = 1},
    {.name = "bad_accept", .bad_accept = true},
    {.name = "masked", .mask_echo = true},
    {.name = "large", .echo_bytes = 65536, .expect_direct = 1},
    {.name = "book", .quotes = 2},
    {.name = "book_fragment", .quotes = 2, .fragment_quotes = true, .write_chunk = 13,
     .expect_direct = 1},
    {.name = "book_tls12", .quotes = 2, .tls12 = true, .expect_direct = 0},
    {.name = "book_budget", .quotes = 2, .fragment_quotes = true, .write_chunk = 1,
     .write_until_empty = true},
    {.name = "book_batch", .quotes = 3000},
    {.name = "book_openssl", .quotes = 2, .direct_tls = false, .expect_direct = 0},
    {.name = "book_keyupdate", .quotes = 4, .key_update = true, .expect_direct = 1},
};
int run(int argc, char **argv) {
    check(argc == 3 or argc == 4);
    std::string name = argc == 4 ? argv[3] : "";
    // Optional cipher-suite suffix exercises each AEAD supported by the direct reader.
    std::string suite;
    for (auto [suffix, cipher] : {std::pair{"_aes128", "TLS_AES_128_GCM_SHA256"},
                                  std::pair{"_chacha", "TLS_CHACHA20_POLY1305_SHA256"}})
        if (name.ends_with(suffix)) {
            name.resize(name.size() - std::string_view(suffix).size());
            suite = cipher;
        }
    auto const *found = std::find_if(std::begin(modes), std::end(modes),
                                     [&](Mode const &m) { return m.name == name; });
    check(found != std::end(modes));
    Mode const &mode = *found;
    bool const book_mode = mode.quotes != 0;
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ctx{SSL_CTX_new(TLS_server_method()),
                                                          SSL_CTX_free};
    check(SSL_CTX_use_certificate_file(ctx.get(), argv[1], SSL_FILETYPE_PEM) == 1);
    check(SSL_CTX_use_PrivateKey_file(ctx.get(), argv[2], SSL_FILETYPE_PEM) == 1);
    if (!suite.empty()) check(SSL_CTX_set_ciphersuites(ctx.get(), suite.c_str()) == 1);
    if (mode.tls12)
        check(SSL_CTX_set_max_proto_version(ctx.get(), TLS1_2_VERSION) == 1);
    std::unique_ptr<SSL, decltype(&SSL_free)> ssl{SSL_new(ctx.get()), SSL_free};
    // Counts KeyUpdate messages the server receives from the client.
    static unsigned client_key_updates{};
    SSL_set_msg_callback(ssl.get(), [](int write_p, int, int content_type, void const *buf,
                                       std::size_t len, SSL *, void *) {
        if (!write_p && content_type == SSL3_RT_HANDSHAKE && len >= 1 &&
            static_cast<unsigned char const *>(buf)[0] == SSL3_MT_KEY_UPDATE)
            ++client_key_updates;
    });
    auto *in = BIO_new(BIO_s_mem());
    auto *out = BIO_new(BIO_s_mem());
    BIO_set_mem_eof_return(in, -1);
    SSL_set_bio(ssl.get(), in, out);
    SSL_set_accept_state(ssl.get());
    std::deque<std::vector<unsigned char>> to_server, to_client;
    TcpManager client({{2, 0, 0, 0, 0, 2}, {192, 0, 2, 2}}, [&](Bytes<> b) {
        to_server.emplace_back(b.begin(), b.end());
        return true;
    });
    TcpManager server({{2, 0, 0, 0, 0, 1}, {192, 0, 2, 1}}, [&](Bytes<> b) {
        to_client.emplace_back(b.begin(), b.end());
        return true;
    });
    TcpConnectionId connection{};
    bool tcp_eof = false;
    server.listen(8443, {.on_open = [&](auto id) { connection = id; },
                         .on_data =
                             [&](auto, PacketSlice s) {
                                 check(for_each_chunk(s, [&](Bytes<> b) {
                                     check(BIO_write(in, b.data(), b.size()) == int(b.size()));
                                 }));
                             },
                         .on_eof = [&](auto) { tcp_eof = true; },
                         .manual_close = true});
    binance::BookTickerParser book_parser("BTCUSDT");
    unsigned quotes{};
    std::vector<unsigned char> later; // book_keyupdate: sent after the server's KeyUpdate.
    bool key_updated = false;
    bench::StageSamples stages{4096,0};
    wss::Client probe(
        client, {{{192, 0, 2, 1}, 40000, 8443, MacAddress{2, 0, 0, 0, 0, 1}},
                 "demo.test",
                 "/echo",
                 argv[1],
                 8443,
                 mode.echo_bytes == 9 ? std::string("hello WSS") : std::string(mode.echo_bytes, 'a'),
                 !book_mode,
                 [&](Bytes<> message) {
                     auto r = book_parser.parse(
                         {reinterpret_cast<char const *>(message.data()), message.size()});
                     check(r.kind == binance::MessageKind::Quote and r.quote.update_id == ++quotes);
                 },
                 &stages,
                 mode.direct_tls});
    std::vector<protocol::ReceiveTrace> client_traces; // TCP packets seen by the client
    auto deliver = [&](auto &q, TcpManager &m, MacAddress mac) {
        while (not q.empty()) {
            auto b = std::move(q.front());
            q.pop_front();
            rte_mbuf p{};
            p.buf_addr = b.data();
            p.pkt_len = b.size();
            p.data_len = b.size();
            p.nb_segs = 1;
            auto ip = IPv4View::parse({&p, 14, p.pkt_len - 14});
            check(bool(ip));
            auto tcp = TcpView::parse(*ip);
            check(bool(tcp));
            protocol::ReceiveTrace trace{.begin_ns=bench::now_ns(), .bytes=p.pkt_len, .transport=6};
            m.receive(*ip, *tcp, mac, TcpManager::Clock::now(), &trace);
            if (&m == &client) stages.record_packet(trace);
            if (&m == &client) client_traces.push_back(trace);
        }
    };
    bool tls_ready = false, upgrade = false, closing = false, shutdown = false;
    std::string request;
    std::vector<unsigned char> ws, tx, tcp_tx;
    for (unsigned step = 0; step < 50000 and not probe.done(); ++step) {
        auto now = TcpManager::Clock::now();
        client.poll(now);
        server.poll(now);
        deliver(to_server, server, {2, 0, 0, 0, 0, 2});
        deliver(to_client, client, {2, 0, 0, 0, 0, 1});
        probe.poll(now);
        probe.warm(); // Must never disturb the live connection, in any state.
        if (not tls_ready) {
            auto r = SSL_do_handshake(ssl.get());
            if (r == 1)
                tls_ready = true;
            else {
                auto e = SSL_get_error(ssl.get(), r);
                check(e == SSL_ERROR_WANT_READ or e == SSL_ERROR_WANT_WRITE);
            }
        }
        if (tls_ready and not shutdown) {
            unsigned char buf[16384];
            std::size_t n{};
            auto r = SSL_read_ex(ssl.get(), buf, sizeof(buf), &n);
            if (r == 1) {
                if (not upgrade) {
                    request.append(reinterpret_cast<char *>(buf), n);
                    auto end = request.find("\r\n\r\n");
                    if (end != request.npos) {
                        auto pos = request.find("Sec-WebSocket-Key: ");
                        check(pos != request.npos);
                        pos += 19;
                        auto key = request.substr(pos, request.find("\r\n", pos) - pos) +
                                   "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
                        unsigned char digest[20], encoded[32];
                        unsigned length{};
                        check(EVP_Digest(key.data(), key.size(), digest, &length, EVP_sha1(),
                                         nullptr) == 1);
                        auto size = EVP_EncodeBlock(encoded, digest, 20);
                        auto response = std::string("HTTP/1.1 101 Switching Protocols\r\nUpgrade: "
                                                    "websocket\r\nConnection: keep-alive, "
                                                    "Upgrade\r\nSec-WebSocket-Accept: ") +
                                        std::string(reinterpret_cast<char *>(encoded), size) +
                                        "\r\n\r\n";
                        if (mode.bad_accept)
                            response.replace(response.find("Sec-WebSocket-Accept: ") + 22, 1, "!");
                        tx.insert(tx.end(), response.begin(), response.end());
                        upgrade = true;
                        if (book_mode) {
                            for (unsigned u = 1; u <= mode.quotes; ++u) {
                                if (mode.key_update && u == 3)
                                    tx.swap(later); // quotes 3.. go to `later`

                                auto json =
                                    std::string("{\"u\":") + std::to_string(u) +
                                    R"(,"s":"BTCUSDT","b":"1.23","B":"4","a":"2.34","A":"5"})";
                                if (mode.fragment_quotes) {
                                    auto half=json.size()/2;
                                    tx.insert(tx.end(),{1,static_cast<unsigned char>(half)});
                                    tx.insert(tx.end(),json.begin(),json.begin()+half);
                                    tx.insert(tx.end(),{0x89,0,0x80,static_cast<unsigned char>(json.size()-half)});
                                    tx.insert(tx.end(),json.begin()+half,json.end());
                                } else {
                                    tx.push_back(0x81);tx.push_back(json.size());
                                    tx.insert(tx.end(),json.begin(),json.end());
                                }
                            }
                            tx.insert(tx.end(), {0x88, 2, 3, 232});
                            if (mode.key_update)
                                tx.swap(later); // tx: 101 + quotes 1-2; later: 3-4 + close
                        }
                    }
                } else
                    ws.insert(ws.end(), buf, buf + n);
            } else {
                auto e = SSL_get_error(ssl.get(), r);
                if (e == SSL_ERROR_ZERO_RETURN)
                    closing = true;
                else
                    check(e == SSL_ERROR_WANT_READ or e == SSL_ERROR_WANT_WRITE);
            }
            while (ws.size() >= 6) {
                unsigned op = ws[0] & 15;
                std::size_t size = ws[1] & 127;
                check(ws[1] & 128);
                std::size_t h = 2;
                if (size == 126) {
                    if (ws.size() < 4)
                        break;
                    size = (unsigned(ws[2]) << 8) | ws[3];
                    h = 4;
                } else if (size == 127) {
                    if (ws.size() < 10)
                        break;
                    size = 0;
                    for (unsigned i = 2; i < 10; ++i)
                        size = (size << 8) | ws[i];
                    h = 10;
                }
                if (ws.size() < size + h + 4)
                    break;
                if (book_mode and op == 8) {
                    ws.erase(ws.begin(), ws.begin() + h + 4 + size);
                    closing = true;
                    continue;
                }
                if (mode.fragment_echo and op == 1) {
                    auto half = size / 2;
                    tx.push_back(1);
                    tx.push_back(half);
                    for (std::size_t i = 0; i < half; ++i)
                        tx.push_back(ws[h + 4 + i] ^ ws[h + i % 4]);
                    tx.insert(tx.end(), {0x89, 1, 'p'});
                    tx.push_back(0x80);
                    tx.push_back(size - half);
                    for (std::size_t i = half; i < size; ++i)
                        tx.push_back(ws[h + 4 + i] ^ ws[h + i % 4]);
                    ws.erase(ws.begin(), ws.begin() + h + 4 + size);
                    continue;
                }
                tx.push_back(0x80 | op);
                unsigned maskbit = mode.mask_echo ? 128 : 0;
                if (size < 126)
                    tx.push_back(maskbit | size);
                else if (size <= 65535) {
                    tx.push_back(maskbit | 126);
                    tx.push_back(size >> 8);
                    tx.push_back(size);
                } else {
                    tx.push_back(maskbit | 127);
                    for (int i = 7; i >= 0; --i)
                        tx.push_back(std::uint64_t(size) >> (8 * i));
                }
                for (std::size_t i = 0; i < size; ++i)
                    tx.push_back(ws[h + 4 + i] ^ ws[h + i % 4]);
                ws.erase(ws.begin(), ws.begin() + h + 4 + size);
                if (op == 8)
                    closing = true;
            }
            while (not tx.empty()) {
                std::size_t n{};
                auto amount = mode.write_chunk ? std::min(mode.write_chunk, tx.size()) : tx.size();
                check(SSL_write_ex(ssl.get(), tx.data(), amount, &n) == 1);
                tx.erase(tx.begin(), tx.begin() + n);
                if (not mode.write_until_empty)
                    break;
            }
            // Wait until the client reads records directly so its KeyUpdate handling is tested.
            if (tx.empty() && !later.empty() && !key_updated && probe.direct_tls_active()) {
                check(SSL_key_update(ssl.get(), SSL_KEY_UPDATE_REQUESTED) == 1);
                key_updated = true;
                tx.swap(later);
            }
            if (closing) {
                auto r = SSL_shutdown(ssl.get());
                if (r == 1)
                    shutdown = true;
                else if (r < 0) {
                    auto e = SSL_get_error(ssl.get(), r);
                    check(e == SSL_ERROR_WANT_READ or e == SSL_ERROR_WANT_WRITE);
                }
            }
        }
        while (BIO_ctrl_pending(out)) {
            unsigned char b[16384];
            auto n = BIO_read(out, b, sizeof(b));
            check(n > 0);
            tcp_tx.insert(tcp_tx.end(), b, b + n);
        }
        if (connection and not tcp_tx.empty()) {
            auto n = server.write(connection, tcp_tx);
            tcp_tx.erase(tcp_tx.begin(), tcp_tx.begin() + n);
        }
        if (shutdown and tcp_tx.empty() and server.flushed(connection))
            (void)server.close(connection, now);
    }
    check(probe.done());
    if (book_mode) {
        check(quotes == mode.quotes && !client_traces.empty());
        bool delivered = false;
        for (auto const &trace : client_traces) {
            check(trace.connection_id == probe.connection_id());
            delivered |= trace.callbacks != 0;
        }
        check(delivered);
        check(!stages.samples(bench::Stage::Tls).empty());
        check(!stages.samples(bench::Stage::PacketToTcp).empty());

    }
    // TLS 1.3 uses direct AEAD reads unless disabled; TLS 1.2 always stays on OpenSSL.
    if (mode.expect_direct >= 0)
        check(probe.direct_tls_active() == (mode.expect_direct == 1));
    if (mode.key_update)
        check(key_updated && client_key_updates == 1);
    std::printf("direct_tls=%d ", probe.direct_tls_active());
    std::puts("PASS: WSS over two production TCP managers, TLS certificate, Upgrade, masked echo "
              "and shutdown");
    return 0;
}

int main(int argc, char **argv) {
    try {
        run(argc, argv);
        return 0;
    } catch (std::exception const &e) {
        std::fprintf(stderr, "%s\n", e.what());
        return 1;
    }
}
