// Compares inbound TLS 1.3 record decryption: OpenSSL SSL_read_ex (memory BIO) versus
// wss::Tls13Reader (EVP AEAD). In-memory only, throwaway self-signed P-256 certificate.
// Usage: tls_direct_bench [count] [suite]
#include "bench/latency.hpp"
#include "wss/tls13_reader.hpp"
#include <cstring>
#include <memory>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
void require(bool ok, char const *what) {
    if (!ok) {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error(what);
    }
}
std::vector<unsigned char> secret;
void keylog(SSL const *, char const *line) {
    std::string_view text{line}, label{"SERVER_TRAFFIC_SECRET_0 "};
    if (!text.starts_with(label)) return;
    auto hex = text.substr(text.find(' ', label.size()) + 1);
    secret.clear();
    for (std::size_t i = 0; i < hex.size(); i += 2)
        secret.push_back(static_cast<unsigned char>(std::stoi(std::string(hex.substr(i, 2)), nullptr, 16)));
}
std::vector<unsigned char> drain(BIO *bio) {
    std::vector<unsigned char> out(BIO_ctrl_pending(bio));
    if (!out.empty()) require(BIO_read(bio, out.data(), int(out.size())) == int(out.size()), "BIO_read");
    return out;
}
} // namespace

int main(int argc, char **argv) try {
    if (argc > 3) throw std::invalid_argument("usage: tls_direct_bench [count] [suite]");
    std::size_t count = argc > 1 ? std::stoul(argv[1]) : 20000;
    std::string suite = argc > 2 ? argv[2] : "TLS_AES_256_GCM_SHA384";
    require(count >= 10 && count <= 1000000, "count must be 10..1000000");
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key{EVP_EC_gen("P-256"), EVP_PKEY_free};
    std::unique_ptr<X509, decltype(&X509_free)> cert{X509_new(), X509_free};
    require(key && cert, "key generation");
    auto *name = X509_get_subject_name(cert.get());
    require(X509_set_version(cert.get(), 2) == 1 &&
                ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1) == 1 &&
                X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0) &&
                X509_gmtime_adj(X509_getm_notAfter(cert.get()), 3600) &&
                X509_set_pubkey(cert.get(), key.get()) == 1 &&
                X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                           reinterpret_cast<unsigned char const *>("bench"), -1,
                                           -1, 0) == 1 &&
                X509_set_issuer_name(cert.get(), name) == 1 &&
                X509_sign(cert.get(), key.get(), EVP_sha256()) > 0,
            "self-signed certificate");
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> sctx{SSL_CTX_new(TLS_server_method()), SSL_CTX_free},
        cctx{SSL_CTX_new(TLS_client_method()), SSL_CTX_free};
    require(SSL_CTX_use_certificate(sctx.get(), cert.get()) == 1 &&
                SSL_CTX_use_PrivateKey(sctx.get(), key.get()) == 1 &&
                SSL_CTX_set_ciphersuites(sctx.get(), suite.c_str()) == 1, "server setup");
    SSL_CTX_set_keylog_callback(cctx.get(), keylog);
    std::unique_ptr<SSL, decltype(&SSL_free)> s{SSL_new(sctx.get()), SSL_free}, c{SSL_new(cctx.get()), SSL_free};
    BIO *s_in = BIO_new(BIO_s_mem()), *s_out = BIO_new(BIO_s_mem());
    BIO *c_in = BIO_new(BIO_s_mem()), *c_out = BIO_new(BIO_s_mem());
    for (auto *b : {s_in, s_out, c_in, c_out}) BIO_set_mem_eof_return(b, -1);
    SSL_set_bio(s.get(), s_in, s_out);
    SSL_set_bio(c.get(), c_in, c_out);
    SSL_set_accept_state(s.get());
    SSL_set_connect_state(c.get());
    for (int i = 0; i < 20 && !(SSL_is_init_finished(s.get()) && SSL_is_init_finished(c.get())); ++i) {
        SSL_do_handshake(c.get());
        auto b = drain(c_out); BIO_write(s_in, b.data(), int(b.size()));
        SSL_do_handshake(s.get());
        b = drain(s_out); BIO_write(c_in, b.data(), int(b.size()));
    }
    require(SSL_is_init_finished(c.get()), "handshake");
    // Let the client consume session tickets plus one marker record through OpenSSL.
    unsigned char buf[16384];
    std::size_t n{};
    SSL_write_ex(s.get(), "sync", 4, &n);
    auto b = drain(s_out); BIO_write(c_in, b.data(), int(b.size()));
    require(SSL_read_ex(c.get(), buf, sizeof buf, &n) == 1, "sync read");
    // Pre-encrypt 2*count Binance-sized WebSocket messages, one record each.
    std::string msg = std::string("\x81\x6e") +
        R"({"u":123456789,"s":"BTCUSDT","b":"67000.01000000","B":"0.50000000","a":"67000.02000000","A":"1.25000000"})";
    std::vector<std::vector<unsigned char>> records(2 * count);
    for (auto &r : records) {
        require(SSL_write_ex(s.get(), msg.data(), msg.size(), &n) == 1, "write");
        r = drain(s_out);
    }
    std::vector<unsigned char> evict(8 << 20);
    auto flush_cache = [&] { for (std::size_t j = 0; j < evict.size(); j += 64) evict[j] += 1; };
    // OpenSSL path: write ciphertext to the memory BIO, then SSL_read_ex (as wss::Client did).
    std::vector<std::uint64_t> hot, cold;
    std::size_t cold_every = 10;
    for (std::size_t i = 0; i < count; ++i) {
        bool is_cold = i % cold_every == 0;
        if (is_cold) flush_cache();
        auto t = bench::now_ns();
        BIO_write(c_in, records[i].data(), int(records[i].size()));
        ERR_clear_error();
        require(SSL_read_ex(c.get(), buf, sizeof buf, &n) == 1 && n == msg.size(), "SSL_read_ex");
        (is_cold ? cold : hot).push_back(bench::now_ns() - t);
    }
    std::printf("suite=%s record=%zu bytes\n", suite.c_str(), records[0].size());
    bench::summarize("openssl.hot", hot);
    bench::summarize("openssl.cold", cold);
    hot.clear(); cold.clear();
    wss::Tls13Reader reader;
    auto *cipher = SSL_get_current_cipher(c.get());
    require(reader.configure(SSL_CIPHER_get_protocol_id(cipher), {secret.data(), secret.size()}), "configure");
    // OpenSSL consumed tickets, the marker and `count` records; search just past that.
    std::uint64_t seq = count;
    while (!reader.open(records[count], buf, seq)) require(++seq < count + 64, "sequence");
    for (std::size_t i = count; i < 2 * count; ++i, ++seq) {
        bool is_cold = i % cold_every == 0;
        if (is_cold) flush_cache();
        auto t = bench::now_ns();
        auto opened = reader.open(records[i], buf, seq);
        require(opened && opened->type == 23 && opened->length == msg.size(), "direct open");
        (is_cold ? cold : hot).push_back(bench::now_ns() - t);
    }
    bench::summarize("direct.hot", hot);
    bench::summarize("direct.cold", cold);
} catch (std::exception const &e) {
    std::fprintf(stderr, "%s\n", e.what());
    return 1;
}
