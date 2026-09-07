#include "encoder.hpp"

namespace crypto::rc4 {

Encoder::Encoder(const std::vector<uint8_t> &key) { KSA(key); }

void Encoder::mutate(const std::vector<uint8_t> &key) { KSA(key); }

void Encoder::encode(std::vector<uint8_t> &data) {
    for (auto &byte : data) {
        byte ^= PRGA();
    }
}

void Encoder::KSA(const std::vector<uint8_t> &key) {
    for (auto i = 0; i < S_SIZE; i++) {
        m_S[i] = i;
    }

    m_i = 0;
    m_j = 0;

    size_t j = 0;
    for (auto i = 0; i < S_SIZE; i++) {
        j = (j + m_S[i] + key[i % key.size()]) % S_SIZE;
        std::swap(m_S[i], m_S[j]);
    }
}

uint8_t Encoder::PRGA() {
    m_i = (m_i + 1) % S_SIZE;
    m_j = (m_j + m_S[m_i]) % S_SIZE;

    std::swap(m_S[m_i], m_S[m_j]);

    auto const t = (m_S[m_i] + m_S[m_j]) % S_SIZE;

    return m_S[t];
}

} // namespace crypto::rc4
