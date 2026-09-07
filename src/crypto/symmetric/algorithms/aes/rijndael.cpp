#include "rijndael.hpp"

#include "math/gf2n/gf2n_polynomial.hpp"
#include "rijndael_sbox.hpp"
#include <stdexcept>

namespace crypto::aes {

Rijndael::Rijndael(size_t block_bits) {
    if (block_bits != 128 && block_bits != 192 && block_bits != 256) {
        throw std::invalid_argument("Rijndael: unsupported block size");
    }
    m_block_bytes = block_bits / 8;
    m_nb = m_block_bytes / 4;
    m_sbox = build_sbox(RIJNDAEL_MODULUS);
    m_inv_sbox = build_inv_sbox(RIJNDAEL_MODULUS);
}

void Rijndael::set_encryption_key(const Bytes &key) {
    expand_key(key);
}

void Rijndael::set_decryption_key(const Bytes &key) {
    expand_key(key);
}

void Rijndael::expand_key(const Bytes &key) {
    if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
        throw std::invalid_argument("Rijndael: unsupported key size");
    }
    m_nk = key.size() / 4;
    m_rounds = m_nb > m_nk ? m_nb + 6 : m_nk + 6;

    std::vector<uint32_t> words(m_nb * (m_rounds + 1), 0);
    for (size_t i = 0; i < m_nk; ++i) {
        words[i] = static_cast<uint32_t>(key[4 * i]) << 24 |
                   static_cast<uint32_t>(key[4 * i + 1]) << 16 |
                   static_cast<uint32_t>(key[4 * i + 2]) << 8 |
                   static_cast<uint32_t>(key[4 * i + 3]);
    }

    size_t i = m_nk;
    while (i < words.size()) {
        uint32_t temp = words[i - 1];
        if (i % m_nk == 0) {
            temp = static_cast<uint32_t>(m_sbox[(temp >> 24) & 0xFF]) << 24 |
                   static_cast<uint32_t>(m_sbox[(temp >> 16) & 0xFF]) << 16 |
                   static_cast<uint32_t>(m_sbox[(temp >> 8) & 0xFF]) << 8 |
                   static_cast<uint32_t>(m_sbox[temp & 0xFF]);
            temp = static_cast<uint32_t>(rcon(static_cast<uint8_t>(i / m_nk))) << 24 ^
                   ((temp << 8) | (temp >> 24));
        } else if (m_nk > 6 && i % m_nk == 4) {
            temp = static_cast<uint32_t>(m_sbox[(temp >> 24) & 0xFF]) << 24 |
                   static_cast<uint32_t>(m_sbox[(temp >> 16) & 0xFF]) << 16 |
                   static_cast<uint32_t>(m_sbox[(temp >> 8) & 0xFF]) << 8 |
                   static_cast<uint32_t>(m_sbox[temp & 0xFF]);
        }
        words[i] = words[i - m_nk] ^ temp;
        ++i;
    }

    m_expanded_key.resize(words.size() * 4);
    for (size_t j = 0; j < words.size(); ++j) {
        m_expanded_key[4 * j] = static_cast<uint8_t>(words[j] >> 24);
        m_expanded_key[4 * j + 1] = static_cast<uint8_t>(words[j] >> 16);
        m_expanded_key[4 * j + 2] = static_cast<uint8_t>(words[j] >> 8);
        m_expanded_key[4 * j + 3] = static_cast<uint8_t>(words[j]);
    }
}

uint8_t Rijndael::rcon(uint8_t index) const {
    uint8_t rc = 0x01;
    for (uint8_t k = 1; k < index; ++k) {
        rc = xtime(rc);
    }
    return rc;
}

size_t Rijndael::block_size() const {
    return m_block_bytes;
}

void Rijndael::add_round_key(std::array<uint8_t, STATE_BYTES> &state,
                             size_t                            round) const {
    for (size_t c = 0; c < m_nb; ++c) {
        for (size_t r = 0; r < 4; ++r) {
            state[4 * c + r] ^= m_expanded_key[round * m_nb * 4 + 4 * c + r];
        }
    }
}

void Rijndael::sub_bytes(std::array<uint8_t, STATE_BYTES> &state,
                         const std::array<uint8_t, 256>   &sbox) const {
    for (size_t i = 0; i < 4 * m_nb; ++i) {
        state[i] = sbox[state[i]];
    }
}

void Rijndael::shift_rows(std::array<uint8_t, STATE_BYTES> &state) const {
    std::array<uint8_t, STATE_BYTES> tmp = state;
    const std::array<size_t, 3>      shifts =
        m_nb == 8 ? std::array<size_t, 3> {1, 3, 4} : std::array<size_t, 3> {1, 2, 3};
    for (size_t r = 0; r < 3; ++r) {
        for (size_t c = 0; c < m_nb; ++c) {
            state[4 * c + (r + 1)] =
                tmp[4 * ((c + shifts[r]) % m_nb) + (r + 1)];
        }
    }
}

void Rijndael::inv_shift_rows(std::array<uint8_t, STATE_BYTES> &state) const {
    std::array<uint8_t, STATE_BYTES> tmp = state;
    const std::array<size_t, 3>      shifts =
        m_nb == 8 ? std::array<size_t, 3> {1, 3, 4} : std::array<size_t, 3> {1, 2, 3};
    for (size_t r = 0; r < 3; ++r) {
        for (size_t c = 0; c < m_nb; ++c) {
            state[4 * c + (r + 1)] =
                tmp[4 * ((c + m_nb - shifts[r]) % m_nb) + (r + 1)];
        }
    }
}

void Rijndael::mix_columns(std::array<uint8_t, STATE_BYTES> &state) const {
    for (size_t c = 0; c < m_nb; ++c) {
        const uint8_t a0 = state[4 * c];
        const uint8_t a1 = state[4 * c + 1];
        const uint8_t a2 = state[4 * c + 2];
        const uint8_t a3 = state[4 * c + 3];
        state[4 * c] = static_cast<uint8_t>(gf_mult(a0, 2) ^ gf_mult(a1, 3) ^ a2 ^ a3);
        state[4 * c + 1] =
            static_cast<uint8_t>(a0 ^ gf_mult(a1, 2) ^ gf_mult(a2, 3) ^ a3);
        state[4 * c + 2] =
            static_cast<uint8_t>(a0 ^ a1 ^ gf_mult(a2, 2) ^ gf_mult(a3, 3));
        state[4 * c + 3] =
            static_cast<uint8_t>(gf_mult(a0, 3) ^ a1 ^ a2 ^ gf_mult(a3, 2));
    }
}

void Rijndael::inv_mix_columns(std::array<uint8_t, STATE_BYTES> &state) const {
    for (size_t c = 0; c < m_nb; ++c) {
        const uint8_t a0 = state[4 * c];
        const uint8_t a1 = state[4 * c + 1];
        const uint8_t a2 = state[4 * c + 2];
        const uint8_t a3 = state[4 * c + 3];
        state[4 * c] = static_cast<uint8_t>(
            gf_mult(a0, 14) ^ gf_mult(a1, 11) ^ gf_mult(a2, 13) ^ gf_mult(a3, 9));
        state[4 * c + 1] = static_cast<uint8_t>(
            gf_mult(a0, 9) ^ gf_mult(a1, 14) ^ gf_mult(a2, 11) ^ gf_mult(a3, 13));
        state[4 * c + 2] = static_cast<uint8_t>(
            gf_mult(a0, 13) ^ gf_mult(a1, 9) ^ gf_mult(a2, 14) ^ gf_mult(a3, 11));
        state[4 * c + 3] = static_cast<uint8_t>(
            gf_mult(a0, 11) ^ gf_mult(a1, 13) ^ gf_mult(a2, 9) ^ gf_mult(a3, 14));
    }
}

uint8_t Rijndael::xtime(uint8_t a) {
    return static_cast<uint8_t>((a << 1) ^ (a & 0x80 ? 0x1B : 0x00));
}

uint8_t Rijndael::gf_mult(uint8_t a, uint8_t b) {
    return static_cast<uint8_t>(math::gf2n::Gf2nPolynomial::mul_mod(
                                    math::gf2n::Gf2nPolynomial(a),
                                    math::gf2n::Gf2nPolynomial(b),
                                    math::gf2n::Gf2nPolynomial(RIJNDAEL_MODULUS))
                                    .bits());
}

Bytes Rijndael::encrypt_block(const Bytes &block) const {
    if (block.size() != m_block_bytes) {
        throw std::invalid_argument("Rijndael: block size mismatch");
    }
    if (m_expanded_key.empty()) {
        throw std::invalid_argument("Rijndael: key not set");
    }

    std::array<uint8_t, STATE_BYTES> state {};
    for (size_t i = 0; i < m_block_bytes; ++i) {
        state[i] = block[i];
    }

    add_round_key(state, 0);
    for (size_t round = 1; round < m_rounds; ++round) {
        sub_bytes(state, m_sbox);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, round);
    }
    sub_bytes(state, m_sbox);
    shift_rows(state);
    add_round_key(state, m_rounds);

    return Bytes(state.begin(), state.begin() + static_cast<std::ptrdiff_t>(m_block_bytes));
}

Bytes Rijndael::decrypt_block(const Bytes &block) const {
    if (block.size() != m_block_bytes) {
        throw std::invalid_argument("Rijndael: block size mismatch");
    }
    if (m_expanded_key.empty()) {
        throw std::invalid_argument("Rijndael: key not set");
    }

    std::array<uint8_t, STATE_BYTES> state {};
    for (size_t i = 0; i < m_block_bytes; ++i) {
        state[i] = block[i];
    }

    add_round_key(state, m_rounds);
    for (size_t round = m_rounds - 1; round > 0; --round) {
        inv_shift_rows(state);
        sub_bytes(state, m_inv_sbox);
        add_round_key(state, round);
        inv_mix_columns(state);
    }
    inv_shift_rows(state);
    sub_bytes(state, m_inv_sbox);
    add_round_key(state, 0);

    return Bytes(state.begin(), state.begin() + static_cast<std::ptrdiff_t>(m_block_bytes));
}

} // namespace crypto::aes
