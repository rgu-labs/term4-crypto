
#pragma once

#include "internal/core/symmetric_cipher.hpp"
#include <array>
#include <cstdint>

namespace crypto::mars {

class MARS final : public core::SymmetricCipher {
  public:
    explicit MARS() = default;

    void set_encryption_key(const Bytes &key) override;
    void set_decryption_key(const Bytes &key) override;

    Bytes encrypt_block(const Bytes &block) const override;
    Bytes decrypt_block(const Bytes &block) const override;

    size_t block_size() const override;

  private:
    static constexpr size_t BLOCK_SIZE = 16;
    static constexpr size_t KEY_WORDS = 40;

    std::array<uint32_t, KEY_WORDS> m_K {};

    static const uint32_t SBOX[512];

    void key_schedule(const Bytes &key);

    static uint32_t rol32(uint32_t x, int n);
    static uint32_t ror32(uint32_t x, int n);

    static void e_func(uint32_t A, uint32_t Kei, uint32_t Koi,
                       uint32_t &L, uint32_t &M, uint32_t &R);

    static void forward_mix(uint32_t &A, uint32_t &B, uint32_t &C, uint32_t &D,
                            const std::array<uint32_t, KEY_WORDS> &K);
    static void backwards_mix(uint32_t &A, uint32_t &B, uint32_t &C, uint32_t &D,
                              const std::array<uint32_t, KEY_WORDS> &K);
    static void core_encrypt(uint32_t &A, uint32_t &B, uint32_t &C, uint32_t &D,
                             const std::array<uint32_t, KEY_WORDS> &K);
    static void core_decrypt(uint32_t &A, uint32_t &B, uint32_t &C, uint32_t &D,
                             const std::array<uint32_t, KEY_WORDS> &K);
};

} // namespace crypto::mars
