#include "feistel_network.hpp"
#include <algorithm>
#include <stdexcept>

namespace crypto::core {

FeistelNetwork::FeistelNetwork(KeyExpansion         &key_expansion,
                               FeistelRoundFunction &round_function,
                               size_t rounds, size_t block_size) : m_key_expansion(key_expansion), m_round_function(round_function),
                                                                   m_rounds(rounds), m_block_size(block_size) {

    if (rounds == 0) {
        throw std::invalid_argument("Number of rounds can't be 0");
    }
    if (rounds % 2 != 0) {
        throw std::invalid_argument("Number of rounds should be even");
    }
}

void FeistelNetwork::set_encryption_key(const Bytes &key) {
    m_enc_round_keys = m_key_expansion.expand(key);
    validate_round_keys(m_enc_round_keys);
}

void FeistelNetwork::set_decryption_key(const Bytes &key) {
    m_dec_round_keys = m_key_expansion.expand(key);
    validate_round_keys(m_dec_round_keys);
    std::reverse(m_dec_round_keys.begin(), m_dec_round_keys.end());
}

Bytes FeistelNetwork::encrypt_block(const Bytes &plain) const {
    return process_block(plain, m_enc_round_keys);
}

Bytes FeistelNetwork::decrypt_block(const Bytes &cipher) const {
    return process_block(cipher, m_dec_round_keys);
}

Bytes FeistelNetwork::process_block(const Bytes     &block,
                                    const RoundKeys &round_keys) const {
    if (block.size() % 2 != 0) {
        throw std::invalid_argument("FeistelNetwork: block size must be even");
    }

    Bytes b = block;

    const std::size_t half_size = b.size() / 2;
    Bytes             left(b.begin(), b.begin() + half_size);
    Bytes             right(b.begin() + half_size, b.end());

    for (int i = 0; i < m_rounds; i++) {
        const Bytes f = m_round_function.apply(right, round_keys[i]);
        if (f.size() != half_size) {
            throw std::runtime_error("Feistel round function returned invalid size");
        }

        Bytes new_right(half_size);
        for (int j = 0; j < half_size; j++) {
            new_right[j] = left[j] ^ f[j];
        }

        left = right;
        right = std::move(new_right);
    }

    Bytes result;
    result.reserve(b.size());
    result.insert(result.end(), right.begin(), right.end());
    result.insert(result.end(), left.begin(), left.end());

    return result;
}

void FeistelNetwork::validate_round_keys(const RoundKeys &round_keys) const {
    if (round_keys.size() < m_rounds) {
        throw std::invalid_argument("FeistelNetwork: not enough round keys");
    }
}

size_t FeistelNetwork::block_size() const { return m_block_size; }

} // namespace crypto::core
