#include "cipher_context.hpp"
#include "mode/modes.hpp"
#include "padding/padding.hpp"

#include <fstream>
#include <iterator>
#include <stdexcept>

namespace crypto {

void SymmetricCipherContext::set_encryption_key(const Bytes &key) const {
    m_cipher->set_encryption_key(key);
}

void SymmetricCipherContext::set_decryption_key(const Bytes &key) const {
    m_cipher->set_decryption_key(key);
}

void SymmetricCipherContext::encrypt(const Bytes &input, Bytes &output,
                                     size_t threads) const {
    const size_t bs = m_cipher->block_size();
    Bytes        padded = m_padding->apply(input, bs);
    m_mode->encrypt(*m_cipher, padded, output, threads);
}

void SymmetricCipherContext::decrypt(const Bytes &input, Bytes &output,
                                     size_t threads) const {
    Bytes raw;
    m_mode->decrypt(*m_cipher, input, raw, threads);
    output = m_padding->remove(raw, m_cipher->block_size());
}

std::future<void> SymmetricCipherContext::encrypt_file(const std::string &input_path,
                                                       const std::string &output_path,
                                                       size_t             threads) const {
    return std::async(std::launch::async,
                      [this, input_path, output_path, threads]() {
                          Bytes raw = read_file(input_path);
                          Bytes result;
                          encrypt(raw, result, threads);
                          write_file(output_path, result);
                      });
}

std::future<void> SymmetricCipherContext::decrypt_file(const std::string &input_path,
                                                       const std::string &output_path,
                                                       size_t             threads) const {
    return std::async(std::launch::async,
                      [this, input_path, output_path, threads]() {
                          Bytes raw = read_file(input_path);
                          Bytes result;
                          decrypt(raw, result, threads);
                          write_file(output_path, result);
                      });
}

size_t SymmetricCipherContext::cipher_block_size() const { return m_cipher->block_size(); }

Bytes SymmetricCipherContext::read_file(const std::string &path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error(
            "CipherContext: cannot open file for reading: " + path);
    }
    return Bytes(std::istreambuf_iterator<char>(file),
                 std::istreambuf_iterator<char>());
}

void SymmetricCipherContext::write_file(const std::string &path,
                                        const Bytes       &data) {
    std::ofstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error(
            "CipherContext: cannot open file for writing: " + path);
    }
    file.write(reinterpret_cast<const char *>(data.data()), data.size());
    if (!file) {
        throw std::runtime_error("CipherContext: write error: " + path);
    }
}

void SymmetricCipherContext::build_mode() {
    switch (m_enc_mode) {
        case SymmetricEncryptionMode::ECB:
            m_mode = std::make_unique<mode::ECB>();
            break;
        case SymmetricEncryptionMode::CBC:
            m_mode = std::make_unique<mode::CBC>(m_iv);
            break;
        case SymmetricEncryptionMode::PCBC:
            m_mode = std::make_unique<mode::PCBC>(m_iv);
            break;
        case SymmetricEncryptionMode::CFB:
            m_mode = std::make_unique<mode::CFB>(m_iv);
            break;
        case SymmetricEncryptionMode::OFB:
            m_mode = std::make_unique<mode::OFB>(m_iv);
            break;
        case SymmetricEncryptionMode::CTR:
            m_mode = std::make_unique<mode::CTR>(m_iv);
            break;
        case SymmetricEncryptionMode::RD:
            m_mode = std::make_unique<mode::RD>();
            break;
        default:
            throw std::invalid_argument("CipherContext: unknown encryption mode");
    }
}

void SymmetricCipherContext::build_padding() {
    switch (m_pad_scheme) {
        case SymmetricPaddingScheme::Zeros:
            m_padding = std::make_unique<padding::ZerosPadding>();
            break;
        case SymmetricPaddingScheme::AnsiX923:
            m_padding = std::make_unique<padding::AnsiX923Padding>();
            break;
        case SymmetricPaddingScheme::ISO10126:
            m_padding = std::make_unique<padding::ISO10126Padding>();
            break;
        case SymmetricPaddingScheme::PKCS7:
            m_padding = std::make_unique<padding::PKCS7Padding>();
            break;
        default:
            throw std::invalid_argument("CipherContext: unknown padding scheme");
    }
}

} // namespace crypto
