
#pragma once

#include "internal/core/symmetric_cipher.hpp"
#include "symmetric/mode/cipher_mode.hpp"
#include "symmetric/padding/padding.hpp"

#include <future>
#include <memory>
#include <string>

namespace crypto {

enum class SymmetricEncryptionMode {
    ECB,
    CBC,
    PCBC,
    CFB,
    OFB,
    CTR,
    RD,
};

enum class SymmetricPaddingScheme {
    Zeros,
    AnsiX923,
    PKCS7,
    ISO10126,
};

class SymmetricCipherContext {
  public:
    SymmetricCipherContext(std::unique_ptr<core::SymmetricCipher> cipher,
                           const SymmetricEncryptionMode enc_mode, const SymmetricPaddingScheme pad_scheme,
                           Bytes iv = {}) : m_cipher(std::move(cipher)),
                                            m_enc_mode(enc_mode),
                                            m_pad_scheme(pad_scheme),
                                            m_iv(std::move(iv)) {
        if (!m_cipher) {
            throw std::invalid_argument("CipherContext: cipher must not be null");
        }
        build_mode();
        build_padding();
    }

    void set_encryption_key(const Bytes &key) const;
    void set_decryption_key(const Bytes &key) const;

    void encrypt(const Bytes &input, Bytes &output, size_t threads = 1) const;
    void decrypt(const Bytes &input, Bytes &output, size_t threads = 1) const;

    std::future<void> encrypt_file(const std::string &input_path,
                                   const std::string &output_path,
                                   size_t             threads = 1) const;
    std::future<void> decrypt_file(const std::string &input_path,
                                   const std::string &output_path,
                                   size_t             threads = 1) const;
    size_t            cipher_block_size() const;

  private:
    static Bytes read_file(const std::string &path);
    static void  write_file(const std::string &path, const Bytes &data);

    void build_mode();
    void build_padding();

    std::unique_ptr<core::SymmetricCipher>         m_cipher;
    std::unique_ptr<mode::SymmetricCipherMode>     m_mode;
    std::unique_ptr<padding::SymmetricPaddingMode> m_padding;
    SymmetricEncryptionMode                        m_enc_mode;
    SymmetricPaddingScheme                         m_pad_scheme;
    Bytes                                          m_iv;
};

} // namespace crypto
