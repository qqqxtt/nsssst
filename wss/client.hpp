#pragma once
#include "tcp_manager.hpp"
#include "bench/stages.hpp"
#include "tls13_reader.hpp"
#include <memory>
#include <openssl/ssl.h>
#include <string>
namespace wss {
struct Config {
    protocol::TcpConnectOptions tcp;
    std::string hostname, path, ca_file;
    std::uint16_t port{8443};
    std::string message{"hello WSS"};
    bool echo_probe{true};
    // Complete WS message, borrowed for the duration of the call only.
    std::function<void(protocol::Bytes<>)> on_message;
    bench::StageSamples *stats{}; // Borrowed; must outlive the client.
    // TLS 1.3 only: after the WebSocket upgrade, decrypt inbound records with EVP AEAD
    // instead of SSL_read. Sending, TLS 1.2 and any unexpected state stay on OpenSSL.
    bool direct_tls{true};
};
// Echo probe by default; echo_probe=false enables persistent message callbacks.
// Destructor cancels an active TCP connection and clears callbacks (TIME_WAIT is preserved).
class Client {
  public:
    Client(protocol::TcpManager &, Config);
    ~Client();
    Client(Client const &) = delete;
    Client &operator=(Client const &) = delete;
    void poll(protocol::TcpManager::Clock::time_point now);
    protocol::TcpConnectionId connection_id() const noexcept { return id_; }
    bool input_ready() const noexcept { return input_ready_; }
    bool done() const { return done_; }
    bool direct_tls_active() const noexcept { return direct_; }
    // Idle cache warm-up: runs the AEAD decrypt path on a dummy record. No state changes.
    void warm();

  private:
    static constexpr std::size_t input_limit = 131072;
    protocol::Bytes<> received() const noexcept {
        return {incoming_.data() + input_head_, input_tail_ - input_head_};
    }
    void consume_input(std::size_t n) noexcept {
        input_head_ += n;
        if (input_head_ == input_tail_) input_head_ = input_tail_ = 0;
    }
    void drive();
    void parse();
    void frame(unsigned opcode, protocol::Bytes<> bytes);
    void fail(char const *reason);
    static void keylog(SSL const *ssl, char const *line);
    void start_direct();
    void read_direct();
    void fallback_to_openssl();
    void post_handshake(protocol::Bytes<> bytes);
    void alert(protocol::Bytes<> bytes);
    protocol::TcpManager &tcp_;
    Config config_;
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ctx_{nullptr, SSL_CTX_free};
    std::unique_ptr<SSL, decltype(&SSL_free)> ssl_{nullptr, SSL_free};
    BIO *input_{}, *output_{}; // Owned by SSL.
    protocol::TcpConnectionId id_{};
    std::string key_, expected_;
    // Full-sized storage: writes and JSON padding never access vector capacity outside size.
    std::vector<unsigned char> incoming_ = std::vector<unsigned char>(input_limit + 4096);
    std::size_t input_head_{}, input_tail_{};
    std::array<unsigned char, 16384> output_scratch_{};
    bool input_ready_{};
    // Independent wire framing also works when OpenSSL has consumed a partial record.
    std::array<unsigned char, 5> input_header_{};
    std::size_t input_record_used_{}, input_record_length_{};
    void note_input(protocol::Bytes<> bytes) noexcept {
        while (!bytes.empty()) {
            auto n = std::min(bytes.size(), input_record_used_ < 5
                ? 5 - input_record_used_ : input_record_length_ - input_record_used_);
            if (input_record_used_ < 5)
                std::copy_n(bytes.begin(), n, input_header_.begin() + input_record_used_);
            input_record_used_ += n;
            bytes = bytes.subspan(n);
            if (input_record_used_ == 5)
                input_record_length_ = 5 + (unsigned(input_header_[3]) << 8) + input_header_[4];
            if (input_record_used_ >= 5 && input_record_used_ == input_record_length_) {
                input_ready_ = true;
                input_record_used_ = 0;
            }
        }
    }
    std::vector<unsigned char> plain_, writing_, encrypted_, message_;
    enum class State { Connecting, Handshake, Upgrade, Open, Closing, Shutdown, Closed };
    State state_{State::Connecting};
    bool echo_verified_{}, connected_{}, eof_{}, done_{}, peer_close_{}, sent_close_{},
        shutdown_done_{};
    unsigned fragment_{};
    protocol::TcpManager::Clock::time_point deadline_;
    // Direct TLS 1.3 receive state.
    std::array<unsigned char, 48> server_secret_{};
    std::size_t server_secret_length_{};
    std::unique_ptr<Tls13Reader> reader_;
    std::vector<unsigned char> cipher_, handshake_;
    std::size_t cipher_head_{};
    std::uint64_t read_sequence_{};
    bool direct_{}, direct_failed_{}, sequence_known_{}, tls_close_received_{},
        key_update_reply_{};
    std::array<unsigned char, 5 + 128> warm_record_{23, 3, 3, 0, 128};
    std::array<unsigned char, 128> warm_out_{};
};
} // namespace wss
