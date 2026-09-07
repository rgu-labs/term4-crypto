
#pragma once

#include <cstddef>

#include "feistel_round_function.hpp"
#include "key_expansion.hpp"
#include "symmetric_cipher.hpp"

namespace crypto::core {

using RoundKeys = std::vector<Bytes>;

class FeistelNetwork : public SymmetricCipher {
  public:
    FeistelNetwork(KeyExpansion         &key_expansion,
                   FeistelRoundFunction &round_function, size_t rounds,
                   size_t block_size);

    void set_encryption_key(const Bytes &key) override;
    void set_decryption_key(const Bytes &key) override;

    Bytes encrypt_block(const Bytes &plain) const override;
    Bytes decrypt_block(const Bytes &cipher) const override;

    size_t block_size() const override;

  private:
    Bytes process_block(const Bytes &block, const RoundKeys &round_keys) const;

    void validate_round_keys(const RoundKeys &round_keys) const;

    const KeyExpansion         &m_key_expansion;
    const FeistelRoundFunction &m_round_function;
    size_t                      m_rounds;
    size_t                      m_block_size;

    RoundKeys m_enc_round_keys;
    RoundKeys m_dec_round_keys;
};
} // namespace crypto::core
