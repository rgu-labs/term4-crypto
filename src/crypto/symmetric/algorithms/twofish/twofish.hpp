
#pragma once

#include "internal/core/symmetric_cipher.hpp"
#include <array>
#include <cstdint>

namespace crypto::twofish {

class Twofish final : public core::SymmetricCipher {
  public:
    explicit Twofish() = default;

    void set_encryption_key(const Bytes &key) override;
    void set_decryption_key(const Bytes &key) override;

    Bytes encrypt_block(const Bytes &block) const override;
    Bytes decrypt_block(const Bytes &block) const override;

    size_t block_size() const override;

  private:
    static constexpr size_t BLOCK_SIZE = 16;
    static constexpr size_t ROUNDS = 16;
    static constexpr size_t SUBKEYS_COUNT = 40;

    std::array<uint32_t, SUBKEYS_COUNT>     m_subkeys {};
    std::array<std::array<uint8_t, 256>, 4> m_sbox {};

    int m_k {};

    static const uint8_t Q0[256];
    static const uint8_t Q1[256];
    static const uint8_t MDS[4][4];
    static const uint8_t RS[4][8];

    void key_schedule(const Bytes &key);

    uint32_t        g_func(uint32_t x) const;
    static uint32_t h_func(uint32_t x, const std::array<uint32_t, 4> &L, int k);

    static uint8_t  gf_mult(uint8_t a, uint8_t b, uint8_t poly);
    static uint32_t mds_mult(uint8_t y0, uint8_t y1, uint8_t y2, uint8_t y3);
    static uint32_t rs_mult(const uint8_t *key8, int group);

    static uint32_t rol32(uint32_t x, int n);
    static uint32_t ror32(uint32_t x, int n);

    static uint8_t q_byte(const uint8_t *q, uint8_t x);
};

} // namespace crypto::twofish
