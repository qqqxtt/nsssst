#pragma once
#include "mbuf_slice.hpp"
#include <array>
#include <cstdint>
#include <memory>
#include <openssl/evp.h>
#include <optional>

namespace wss {
// Decrypts inbound TLS 1.3 application-traffic records with EVP AEAD directly,
// bypassing the OpenSSL record layer once the handshake is complete.
// Supports TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256.
class Tls13Reader {
  public:
    static constexpr std::size_t max_ciphertext = 16384 + 256;
    struct Opened {
        unsigned type;      // Inner content type (21 alert, 22 handshake, 23 application data).
        std::size_t length; // Plaintext length without content type and padding.
    };
    Tls13Reader() = default;
    ~Tls13Reader();
    Tls13Reader(Tls13Reader const &) = delete;
    Tls13Reader &operator=(Tls13Reader const &) = delete;

    // suite: IANA cipher suite id (0x1301..0x1303). secret: server application traffic secret.
    [[nodiscard]] bool configure(std::uint16_t suite, protocol::Bytes<> secret);
    // record: one complete record (5-byte header + body). out must hold body - 16 bytes.
    // Returns nullopt when authentication fails (wrong key, sequence number or tampering).
    // Each call re-initialises the AEAD nonce, so a failed call leaves no state behind.
    [[nodiscard]] std::optional<Opened> open(protocol::Bytes<> record, unsigned char *out,
                                             std::uint64_t sequence);
    // KeyUpdate: derive the next generation traffic secret, key and IV (RFC 8446 7.2).
    [[nodiscard]] bool update();

  private:
    bool derive();
    EVP_CIPHER_CTX *ctx_{};
    EVP_CIPHER *cipher_{};
    char const *digest_{};
    std::array<unsigned char, 48> secret_{};
    std::size_t secret_length_{}, key_length_{};
    std::array<unsigned char, 12> iv_{};
};
} // namespace wss
