#include "tls13_reader.hpp"
#include <algorithm>
#include <cstring>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/kdf.h>
#include <string_view>

namespace wss {
namespace {
// HKDF-Expand-Label(secret, label, "", length), RFC 8446 section 7.1.
bool expand_label(char const *digest, protocol::Bytes<> secret, std::string_view label,
                  unsigned char *out, std::size_t length) {
    std::array<unsigned char, 2 + 1 + 255 + 1> info{};
    std::string_view prefix = "tls13 ";
    auto full = prefix.size() + label.size();
    info[0] = static_cast<unsigned char>(length >> 8);
    info[1] = static_cast<unsigned char>(length);
    info[2] = static_cast<unsigned char>(full);
    std::copy(prefix.begin(), prefix.end(), info.begin() + 3);
    std::copy(label.begin(), label.end(), info.begin() + 3 + prefix.size());
    info[3 + full] = 0; // Empty context.
    auto info_length = 4 + full;

    std::unique_ptr<EVP_KDF, decltype(&EVP_KDF_free)> kdf{EVP_KDF_fetch(nullptr, "HKDF", nullptr),
                                                          EVP_KDF_free};
    if (not kdf)
        return false;
    std::unique_ptr<EVP_KDF_CTX, decltype(&EVP_KDF_CTX_free)> ctx{EVP_KDF_CTX_new(kdf.get()),
                                                                  EVP_KDF_CTX_free};
    if (not ctx)
        return false;
    int mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode),
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, const_cast<char *>(digest), 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                          const_cast<unsigned char *>(secret.data()),
                                          secret.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info.data(), info_length),
        OSSL_PARAM_construct_end()};
    return EVP_KDF_derive(ctx.get(), out, length, params) == 1;
}
} // namespace

Tls13Reader::~Tls13Reader() {
    EVP_CIPHER_CTX_free(ctx_);
    EVP_CIPHER_free(cipher_);
    OPENSSL_cleanse(secret_.data(), secret_.size());
    OPENSSL_cleanse(iv_.data(), iv_.size());
}

bool Tls13Reader::configure(std::uint16_t suite, protocol::Bytes<> secret) {
    char const *name{};
    switch (suite) {
    case 0x1301:
        name = "AES-128-GCM", digest_ = "SHA256", key_length_ = 16;
        break;
    case 0x1302:
        name = "AES-256-GCM", digest_ = "SHA384", key_length_ = 32;
        break;
    case 0x1303:
        name = "ChaCha20-Poly1305", digest_ = "SHA256", key_length_ = 32;
        break;
    default:
        return false;
    }
    secret_length_ = suite == 0x1302 ? 48 : 32;
    if (secret.size() != secret_length_)
        return false;
    std::copy(secret.begin(), secret.end(), secret_.begin());
    cipher_ = EVP_CIPHER_fetch(nullptr, name, nullptr);
    ctx_ = EVP_CIPHER_CTX_new();
    return cipher_ and ctx_ and derive();
}

bool Tls13Reader::derive() {
    std::array<unsigned char, 32> key{};
    auto secret = protocol::Bytes<>{secret_.data(), secret_length_};
    bool ok = expand_label(digest_, secret, "key", key.data(), key_length_) and
              expand_label(digest_, secret, "iv", iv_.data(), iv_.size()) and
              EVP_DecryptInit_ex2(ctx_, cipher_, key.data(), nullptr, nullptr) == 1;
    OPENSSL_cleanse(key.data(), key.size());
    return ok;
}

bool Tls13Reader::update() {
    std::array<unsigned char, 48> next{};
    auto ok = expand_label(digest_, {secret_.data(), secret_length_}, "traffic upd", next.data(),
                           secret_length_);
    if (ok) {
        std::copy_n(next.begin(), secret_length_, secret_.begin());
        ok = derive();
    }
    OPENSSL_cleanse(next.data(), next.size());
    return ok;
}

std::optional<Tls13Reader::Opened> Tls13Reader::open(protocol::Bytes<> record, unsigned char *out,
                                                     std::uint64_t sequence) {
    if (not ctx_ or record.size() < 5 + 17 or record.size() > 5 + max_ciphertext)
        return std::nullopt;
    auto body = record.size() - 5;
    auto nonce = iv_;
    for (unsigned i = 0; i < 8; ++i)
        nonce[11 - i] ^= static_cast<unsigned char>(sequence >> (8 * i));
    std::array<unsigned char, 16> tag;
    std::memcpy(tag.data(), record.data() + record.size() - 16, 16);
    int n{}, final_n{};
    if (EVP_DecryptInit_ex2(ctx_, nullptr, nullptr, nonce.data(), nullptr) != 1 or
        EVP_DecryptUpdate(ctx_, nullptr, &n, record.data(), 5) != 1 or
        EVP_DecryptUpdate(ctx_, out, &n, record.data() + 5, static_cast<int>(body - 16)) != 1 or
        EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_AEAD_SET_TAG, 16, tag.data()) != 1 or
        EVP_DecryptFinal_ex(ctx_, out + n, &final_n) != 1)
        return std::nullopt;
    // TLSInnerPlaintext: content || type || zero padding.
    auto length = static_cast<std::size_t>(n + final_n);
    while (length and out[length - 1] == 0)
        --length;
    if (length == 0)
        return Opened{0, 0}; // No content type: unexpected_message, caller rejects.
    return Opened{out[length - 1], length - 1};
}
} // namespace wss
