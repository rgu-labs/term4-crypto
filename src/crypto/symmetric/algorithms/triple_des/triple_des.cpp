#include <stdexcept>

#include "triple_des.hpp"

namespace crypto::des {

TripleDES::TripleDES(TripleDESMode mode) : m_mode(mode) {}

void TripleDES::set_encryption_key(const Bytes &key) {
    init_keys(key);
}

void TripleDES::set_decryption_key(const Bytes &key) {
    init_keys(key);
}

Bytes TripleDES::encrypt_block(const Bytes &block) const {
    return process_block(block, true);
}

Bytes TripleDES::decrypt_block(const Bytes &block) const {
    return process_block(block, false);
}

Bytes TripleDES::process_block(const Bytes &block,
                               bool         encrypting) const {
    Bytes b = block;

    if (encrypting) {
        switch (m_mode) {
            case TripleDESMode::EEE3:
            case TripleDESMode::EEE2:
                b = m_des1.encrypt_block(b);
                b = m_des2.encrypt_block(b);
                b = m_des3.encrypt_block(b);
                break;
            case TripleDESMode::EDE3:
            case TripleDESMode::EDE2:
                b = m_des1.encrypt_block(b);
                b = m_des2.decrypt_block(b);
                b = m_des3.encrypt_block(b);
                break;
        }
    } else {
        switch (m_mode) {
            case TripleDESMode::EEE3:
            case TripleDESMode::EEE2:
                b = m_des3.decrypt_block(b);
                b = m_des2.decrypt_block(b);
                b = m_des1.decrypt_block(b);
                break;
            case TripleDESMode::EDE3:
            case TripleDESMode::EDE2:
                b = m_des3.decrypt_block(b);
                b = m_des2.encrypt_block(b);
                b = m_des1.decrypt_block(b);
                break;
        }
    }

    return b;
}

void TripleDES::init_keys(const Bytes &key) {
    if (key.size() == 16) {
        m_key1 = Bytes(key.begin(), key.begin() + 8);
        m_key2 = Bytes(key.begin() + 8, key.end());
        m_key3 = m_key1;
    } else if (key.size() == 24) {
        m_key1 = Bytes(key.begin(), key.begin() + 8);
        m_key2 = Bytes(key.begin() + 8, key.begin() + 16);
        m_key3 = Bytes(key.begin() + 16, key.end());
    } else {
        throw std::runtime_error("Invalid key length for TripleDES");
    }

    m_des1.set_encryption_key(m_key1);
    m_des1.set_decryption_key(m_key1);
    m_des2.set_encryption_key(m_key2);
    m_des2.set_decryption_key(m_key2);
    m_des3.set_encryption_key(m_key3);
    m_des3.set_decryption_key(m_key3);
}

size_t TripleDES::block_size() const { return m_des1.block_size(); }

} // namespace crypto::des
