#include "feistel_network_wrapper.hpp"

namespace crypto::core {

FeistelNetworkWrapper::FeistelNetworkWrapper(FeistelNetwork &network) : m_network(network) {}

void FeistelNetworkWrapper::set_encryption_key(const Bytes &key) {
    m_network.set_encryption_key(key);
    on_key_set(key, true);
}

void FeistelNetworkWrapper::set_decryption_key(const Bytes &key) {
    m_network.set_decryption_key(key);
    on_key_set(key, false);
}

Bytes FeistelNetworkWrapper::encrypt_block(const Bytes &plain) const {
    Bytes block = plain;
    before_rounds(block, true);
    block = m_network.encrypt_block(block);
    after_rounds(block, true);
    return block;
}

Bytes FeistelNetworkWrapper::decrypt_block(const Bytes &cipher) const {
    Bytes block = cipher;
    before_rounds(block, false);
    block = m_network.decrypt_block(block);
    after_rounds(block, false);
    return block;
}

void FeistelNetworkWrapper::before_rounds(Bytes &, bool) const {}
void FeistelNetworkWrapper::after_rounds(Bytes &, bool) const {}
void FeistelNetworkWrapper::on_key_set(const Bytes &, bool) {}

} // namespace crypto::core
