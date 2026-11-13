#include "client.hpp"
#include <algorithm>
#include <cctype>
#include <cstring>
#include <cstdio>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <string_view>
namespace wss {
using protocol::Bytes;
namespace {
constexpr unsigned read_budget = 16;
std::string base64(Bytes<> b) {
    std::string out(4 * ((b.size() + 2) / 3), '\0');
    EVP_EncodeBlock(reinterpret_cast<unsigned char*>(out.data()), b.data(), b.size());
    return out;
}
} // namespace
Client::Client(protocol::TcpManager& tcp, Config config)
    : tcp_(tcp),
      config_(std::move(config)) {
    if (config_.hostname.empty() or
        config_.hostname.find_first_of("\r\n :/") != std::string::npos or config_.path.empty() or
        config_.path.front() != '/' or config_.path.find_first_of("\r\n ") != std::string::npos or
        config_.message.size() > 65536)
        throw std::invalid_argument("invalid WSS configuration");
    ctx_.reset(SSL_CTX_new(TLS_client_method()));
    if (not ctx_)
        fail("SSL_CTX_new");
    SSL_CTX_set_verify(ctx_.get(), SSL_VERIFY_PEER, nullptr);
    if (SSL_CTX_set_min_proto_version(ctx_.get(), TLS1_2_VERSION) != 1)
        fail("TLS version");
    if (config_.ca_file.empty()
            ? SSL_CTX_set_default_verify_paths(ctx_.get()) != 1
            : SSL_CTX_load_verify_locations(ctx_.get(), config_.ca_file.c_str(), nullptr) != 1)
        fail("TLS trust store");
    if (config_.direct_tls)
        SSL_CTX_set_keylog_callback(ctx_.get(), &Client::keylog); // Captured in memory only.
    ssl_.reset(SSL_new(ctx_.get()));
    if (not ssl_)
        fail("SSL_new");
    SSL_set_app_data(ssl_.get(), this);
    if (SSL_set1_host(ssl_.get(), config_.hostname.c_str()) != 1 or
        SSL_set_tlsext_host_name(ssl_.get(), config_.hostname.c_str()) != 1)
        fail("TLS hostname");
    auto* in = BIO_new(BIO_s_mem());
    auto* out = BIO_new(BIO_s_mem());
    if (not in or not out) {
        BIO_free(in);
        BIO_free(out);
        fail("BIO allocation");
    }
    input_ = in;
    output_ = out;
    BIO_set_mem_eof_return(input_, -1);
    SSL_set_bio(ssl_.get(), input_, output_);
    SSL_set_connect_state(ssl_.get());
    std::array<unsigned char, 16> nonce{};
    if (RAND_bytes(nonce.data(), nonce.size()) != 1)
        fail("random nonce");
    key_ = base64(nonce);
    auto challenge = key_ + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    std::array<unsigned char, EVP_MAX_MD_SIZE> hash{};
    unsigned size{};
    if (EVP_Digest(challenge.data(), challenge.size(), hash.data(), &size, EVP_sha1(), nullptr) !=
        1)
        fail("SHA1");
    expected_ = base64(Bytes<>{hash}.first(size));
    auto now = protocol::TcpManager::Clock::now();
    deadline_ = now + std::chrono::seconds(15);
    id_ = tcp_.connect(config_.tcp,
        {.on_open = [this](auto) { connected_ = true; },
            .on_data =
                [this](auto, protocol::PacketSlice slice) {
                    auto queued = direct_ ? cipher_.size() - cipher_head_ : BIO_ctrl_pending(input_);
                    if (queued + slice.length > 262144)
                        fail("TLS input limit");
                    if (not protocol::for_each_chunk(slice, [this](Bytes<> b) {
                            note_input(b);
                            if (direct_)
                                cipher_.insert(cipher_.end(), b.begin(), b.end());
                            else if (BIO_write(input_, b.data(), b.size()) !=
                                     static_cast<int>(b.size()))
                                fail("BIO input");
                        }))
                        fail("invalid TCP slice");

                },
            .on_eof =
                [this](auto) {
                    input_ready_ = true;
                    eof_ = true;
                    BIO_set_mem_eof_return(input_, 0);
                },
            .on_closed =
                [this](auto, bool error) {
                    if (error)
                        fail("TCP reset/timeout");
                    // poll observes logical close after the callback returns.
                },
            .manual_close = true},
        now);
}
Client::~Client() {
    OPENSSL_cleanse(server_secret_.data(), server_secret_.size());
    if (id_)
        tcp_.abort(id_);
}
void Client::keylog(SSL const *ssl, char const *line) {
    // NSS key log line: "SERVER_TRAFFIC_SECRET_0 <client_random hex> <secret hex>".
    auto *self = static_cast<Client *>(SSL_get_app_data(ssl));
    constexpr std::string_view label = "SERVER_TRAFFIC_SECRET_0 ";
    std::string_view text{line};
    if (not self or not text.starts_with(label))
        return;
    auto space = text.find(' ', label.size());
    if (space == text.npos)
        return;
    auto hex = text.substr(space + 1);
    if (hex.size() % 2 or hex.size() / 2 > self->server_secret_.size())
        return;
    auto digit = [](char c) -> int {
        if (c >= '0' and c <= '9') return c - '0';
        if (c >= 'a' and c <= 'f') return c - 'a' + 10;
        if (c >= 'A' and c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        auto hi = digit(hex[i]), lo = digit(hex[i + 1]);
        if (hi < 0 or lo < 0) {
            OPENSSL_cleanse(self->server_secret_.data(), self->server_secret_.size());
            return;
        }
        self->server_secret_[i / 2] = static_cast<unsigned char>(hi * 16 + lo);
    }
    self->server_secret_length_ = hex.size() / 2;
}
void Client::start_direct() {
    // Switch only on a record boundary with nothing buffered inside OpenSSL, so every
    // later byte from TCP is a complete record that OpenSSL has never seen.
    if (direct_ or direct_failed_ or not config_.direct_tls or state_ != State::Open or eof_ or
        input_record_used_ != 0 or BIO_ctrl_pending(input_) != 0 or SSL_has_pending(ssl_.get()))
        return;
    direct_failed_ = true; // One attempt; stay on OpenSSL if anything is unsupported.
    auto const *cipher = SSL_get_current_cipher(ssl_.get());
    auto reader = std::make_unique<Tls13Reader>();
    bool ok = SSL_version(ssl_.get()) == TLS1_3_VERSION and cipher and server_secret_length_ and
              reader->configure(SSL_CIPHER_get_protocol_id(cipher),
                                {server_secret_.data(), server_secret_length_});
    OPENSSL_cleanse(server_secret_.data(), server_secret_.size());
    server_secret_length_ = 0;
    if (not ok)
        return;
    reader_ = std::move(reader);
    cipher_.reserve(262144 + 2 * Tls13Reader::max_ciphertext);
    direct_failed_ = false;
    direct_ = true;
}
void Client::fallback_to_openssl() {
    auto pending = Bytes<>{cipher_.data() + cipher_head_, cipher_.size() - cipher_head_};
    if (not pending.empty() and
        BIO_write(input_, pending.data(), pending.size()) != static_cast<int>(pending.size()))
        fail("BIO input");
    cipher_.clear();
    cipher_head_ = 0;
    reader_.reset();
    direct_ = false;
    direct_failed_ = true;
    std::fputs("TLS direct read disabled (record sequence not found); using OpenSSL\n", stderr);
}
void Client::read_direct() {
    while (not tls_close_received_) {
        auto available = cipher_.size() - cipher_head_;
        if (available < 5)
            break;
        auto const *header = cipher_.data() + cipher_head_;
        if (header[0] != 23 or header[1] != 3 or header[2] != 3)
            fail("TLS record header");
        std::size_t length = (std::size_t{header[3]} << 8) | header[4];
        if (length < 17 or length > Tls13Reader::max_ciphertext)
            fail("TLS record length");
        if (available < 5 + length)
            break;
        if (input_limit - input_tail_ < length and input_head_) {
            auto kept = input_tail_ - input_head_;
            std::memmove(incoming_.data(), incoming_.data() + input_head_, kept);
            input_head_ = 0;
            input_tail_ = kept;
        }
        if (input_limit - input_tail_ < length)
            fail("WS input limit");
        // Plaintext lands directly behind the unparsed WebSocket bytes: no extra copy.
        auto *out = incoming_.data() + input_tail_;
        Bytes<> record{header, 5 + length};
        auto begin = config_.stats ? bench::now_ns() : 0;
        std::optional<Tls13Reader::Opened> opened;
        if (sequence_known_) {
            opened = reader_->open(record, out, read_sequence_);
            if (not opened)
                fail("TLS record authentication");
        } else {
            // OpenSSL already consumed an unknown number of application records
            // (session tickets, HTTP response). The AEAD tag identifies the next one.
            for (std::uint64_t s = 0; s < 1024 and not opened; ++s)
                if ((opened = reader_->open(record, out, s)))
                    read_sequence_ = s;
            ERR_clear_error();
            if (not opened) {
                fallback_to_openssl();
                return;
            }
            sequence_known_ = true;
        }
        auto end = config_.stats ? bench::now_ns() : 0;
        ++read_sequence_;
        cipher_head_ += 5 + length;
        if (opened->type == 23) {
            if (config_.stats)
                config_.stats->record(bench::Stage::Tls, begin, end, opened->length, id_);
            input_tail_ += opened->length;
            parse();
        } else if (opened->type == 22)
            post_handshake({out, opened->length});
        else if (opened->type == 21)
            alert({out, opened->length});
        else
            fail("TLS inner content type");
    }
    if (cipher_head_ == cipher_.size()) {
        cipher_.clear();
        cipher_head_ = 0;
    } else if (cipher_head_ >= 65536) {
        cipher_.erase(cipher_.begin(), cipher_.begin() + cipher_head_);
        cipher_head_ = 0;
    }
    if (eof_ and not tls_close_received_)
        fail("TLS read/truncated stream");
}
void Client::post_handshake(Bytes<> bytes) {
    if (handshake_.size() + bytes.size() > 65536)
        fail("TLS post-handshake size");
    handshake_.insert(handshake_.end(), bytes.begin(), bytes.end());
    while (handshake_.size() >= 4) {
        auto type = handshake_[0];
        std::size_t length = (std::size_t{handshake_[1]} << 16) |
                             (std::size_t{handshake_[2]} << 8) | handshake_[3];
        if (handshake_.size() < 4 + length)
            break;
        if (type == 24) { // KeyUpdate (RFC 8446 4.6.3): must end its record.
            if (length != 1 or handshake_[4] > 1 or handshake_.size() != 5)
                fail("TLS KeyUpdate");
            if (not reader_->update())
                fail("TLS KeyUpdate derive");
            read_sequence_ = 0;
            if (handshake_[4] == 1) { // update_requested: OpenSSL rolls and announces our key.
                if (SSL_key_update(ssl_.get(), SSL_KEY_UPDATE_NOT_REQUESTED) != 1)
                    fail("TLS KeyUpdate reply");
                key_update_reply_ = true;
            }
        } else if (type != 4) // NewSessionTicket is ignored: no session resumption.
            fail("TLS post-handshake message");
        handshake_.erase(handshake_.begin(), handshake_.begin() + 4 + length);
    }
}
void Client::alert(Bytes<> bytes) {
    if (bytes.size() != 2)
        fail("TLS alert");
    if (bytes[1] == 90) // user_canceled precedes close_notify.
        return;
    if (bytes[1] != 0)
        fail("TLS alert received");
    if (not peer_close_)
        fail("TLS closed before WS close");
    tls_close_received_ = true;
}
void Client::warm() {
    if (direct_ and reader_) // Fails authentication by design; nonce is re-set per call.
        (void)reader_->open(warm_record_, warm_out_.data(), 0);
}
void Client::fail(char const* reason) { throw std::runtime_error(std::string("WSS: ") + reason); }
void Client::drive() {
    if (state_ == State::Handshake) {
        ERR_clear_error();
        auto result = SSL_do_handshake(ssl_.get());
        if (result == 1) {
            state_ = State::Upgrade;
            auto request =
                "GET " + config_.path + " HTTP/1.1\r\nHost: " + config_.hostname + ":" +
                std::to_string(config_.port) +
                "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + key_ +
                "\r\nSec-WebSocket-Version: 13\r\n\r\n";
            plain_.assign(request.begin(), request.end());
        } else {
            auto e = SSL_get_error(ssl_.get(), result);
            if (e != SSL_ERROR_WANT_READ and e != SSL_ERROR_WANT_WRITE)
                fail("TLS handshake/certificate");
        }
    }
    if (state_ == State::Upgrade or state_ == State::Open or state_ == State::Closing) {
        // Idle fast path: with no ciphertext queued, no buffered record and no EOF,
        // SSL_read_ex can only report WANT_READ. Skipping it keeps the busy-poll loop
        // from evicting the RX path from cache on every iteration.
        if (direct_)
            read_direct();
        bool readable = not direct_ and
                        (eof_ or BIO_ctrl_pending(input_) != 0 or SSL_has_pending(ssl_.get()));
        for (unsigned i = 0; readable and i < read_budget; ++i) {
            if (input_limit - input_tail_ < 16384 && input_head_) {
                auto length = input_tail_ - input_head_;
                std::memmove(incoming_.data(), incoming_.data() + input_head_, length);
                input_head_ = 0;
                input_tail_ = length;
            }
            auto room = std::min<std::size_t>(16384, input_limit - input_tail_);
            if (!room) fail("WS input limit");
            std::size_t n{};
            bool measure = config_.stats && (BIO_ctrl_pending(input_) || SSL_has_pending(ssl_.get()));
            ERR_clear_error();
            auto read_begin = measure ? bench::now_ns() : 0;
            auto r = SSL_read_ex(ssl_.get(), incoming_.data() + input_tail_, room, &n);
            auto read_end = measure ? bench::now_ns() : 0;
            if (r == 1) {
                if (measure) config_.stats->record(bench::Stage::Tls, read_begin, read_end, n, id_);
                input_tail_ += n;
                parse();
                // Nothing left to decrypt: skip the extra call that would only say WANT_READ.
                if (BIO_ctrl_pending(input_) == 0 and not SSL_has_pending(ssl_.get()))
                    break;
            } else {
                auto e = SSL_get_error(ssl_.get(), r);
                if (e == SSL_ERROR_ZERO_RETURN) {
                    if (not peer_close_)
                        fail("TLS closed before WS close");
                    break;
                }
                if (e != SSL_ERROR_WANT_READ and e != SSL_ERROR_WANT_WRITE)
                    fail("TLS read/truncated stream");
                break;
            }
        }
        if (not direct_)
            start_direct();
        if (key_update_reply_) {
            ERR_clear_error();
            auto r = SSL_do_handshake(ssl_.get()); // Emits our KeyUpdate into the output BIO.
            if (r == 1)
                key_update_reply_ = false;
            else if (auto e = SSL_get_error(ssl_.get(), r);
                     e != SSL_ERROR_WANT_READ and e != SSL_ERROR_WANT_WRITE)
                fail("TLS KeyUpdate send");
        }
        if (writing_.empty())
            writing_.swap(plain_);
        if (not writing_.empty() and BIO_ctrl_pending(output_) < 65536) {
            std::size_t n{};
            ERR_clear_error();
            auto r = SSL_write_ex(ssl_.get(), writing_.data(), writing_.size(), &n);
            if (r == 1)
                writing_.erase(writing_.begin(), writing_.begin() + n);
            else {
                auto e = SSL_get_error(ssl_.get(), r);
                if (e != SSL_ERROR_WANT_READ and e != SSL_ERROR_WANT_WRITE)
                    fail("TLS write");
            }
        }
        if (peer_close_ and plain_.empty() and writing_.empty())
            state_ = State::Shutdown;
    }
    if (state_ == State::Shutdown and not shutdown_done_) {
        // In direct mode OpenSSL never sees the peer's close_notify; we read it ourselves.
        if (direct_)
            read_direct();
        bool sent = SSL_get_shutdown(ssl_.get()) & SSL_SENT_SHUTDOWN;
        int r = 0;
        if (not (direct_ and sent)) {
            ERR_clear_error();
            r = SSL_shutdown(ssl_.get());
        }
        if (r == 1 or (direct_ and tls_close_received_ and
                       (SSL_get_shutdown(ssl_.get()) & SSL_SENT_SHUTDOWN)))
            shutdown_done_ = true;
        else if (r < 0) {
            auto e = SSL_get_error(ssl_.get(), r);
            if (e != SSL_ERROR_WANT_READ and e != SSL_ERROR_WANT_WRITE)
                fail("TLS shutdown");
        }
    }
}
void Client::poll(protocol::TcpManager::Clock::time_point now) {
    if (done_)
        return;
    if (state_ == State::Closed) {
        if (tcp_.closed(id_)) {
            done_ = true;
            std::puts("PASS: WSS echo, TLS shutdown and TCP close");
        } else if (now >= deadline_)
            fail("TCP close timeout");
        return;
    }
    if (state_ != State::Open and now >= deadline_)
        fail("operation timeout");
    if (connected_ and state_ == State::Connecting)
        state_ = State::Handshake;
    input_ready_ = false;
    drive();
    auto &buffer = output_scratch_;
    while (BIO_ctrl_pending(output_) and encrypted_.size() < 131072) {
        auto n = BIO_read(output_, buffer.data(), buffer.size());
        if (n <= 0)
            break;
        encrypted_.insert(encrypted_.end(), buffer.begin(), buffer.begin() + n);
    }
    if (not encrypted_.empty()) {
        auto n = tcp_.write(id_, encrypted_);
        encrypted_.erase(encrypted_.begin(), encrypted_.begin() + n);
    }
    if (shutdown_done_ and encrypted_.empty() and BIO_ctrl_pending(output_) == 0 and
        tcp_.flushed(id_)) {
        (void)tcp_.close(id_, now);
        state_ = State::Closed;
        deadline_ = now + std::chrono::seconds(15);
    }
}
} // namespace wss
