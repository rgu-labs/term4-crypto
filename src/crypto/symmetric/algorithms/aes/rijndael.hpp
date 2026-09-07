
#pragma once

#include "internal/core/symmetric_cipher.hpp"
#include <array>
#include <cstdint>
#include <vector>

namespace crypto::aes {

class Rijndael final : public core::SymmetricCipher {
  public:
    explicit Rijndael(size_t block_bits = 128);

    void set_encryption_key(const Bytes &key) override;
    void set_decryption_key(const Bytes &key) override;

    Bytes encrypt_block(const Bytes &block) const override;
    Bytes decrypt_block(const Bytes &block) const override;

    size_t block_size() const override;

  private:
    static constexpr size_t MAX_NB = 8;
    static constexpr size_t STATE_BYTES = 4 * MAX_NB;

    size_t                   m_block_bytes = 16;
    size_t                   m_nb = 4;
    size_t                   m_nk = 0;
    size_t                   m_rounds = 0;
    std::vector<uint8_t>     m_expanded_key;
    std::array<uint8_t, 256> m_sbox {};
    std::array<uint8_t, 256> m_inv_sbox {};

    void    expand_key(const Bytes &key);
    uint8_t rcon(uint8_t index) const;

    void add_round_key(std::array<uint8_t, STATE_BYTES> &state, size_t round) const;
    void sub_bytes(std::array<uint8_t, STATE_BYTES> &state,
                   const std::array<uint8_t, 256>   &sbox) const;
    void shift_rows(std::array<uint8_t, STATE_BYTES> &state) const;
    void inv_shift_rows(std::array<uint8_t, STATE_BYTES> &state) const;
    void mix_columns(std::array<uint8_t, STATE_BYTES> &state) const;
    void inv_mix_columns(std::array<uint8_t, STATE_BYTES> &state) const;

    static uint8_t xtime(uint8_t a);
    static uint8_t gf_mult(uint8_t a, uint8_t b);
};

} // namespace crypto::aes
