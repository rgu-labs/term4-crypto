
#pragma once

#include "internal/core/symmetric_cipher.hpp"
#include "crypto/symmetric/algorithms/des/des.hpp"

namespace crypto::des {

enum class TripleDESMode {
    EEE3,
    EDE3,
    EEE2,
    EDE2,
};

class TripleDES final : public core::SymmetricCipher {
  public:
    explicit TripleDES(TripleDESMode mode);

    void set_encryption_key(const Bytes &key) override;
    void set_decryption_key(const Bytes &key) override;

    Bytes encrypt_block(const Bytes &block) const override;
    Bytes decrypt_block(const Bytes &block) const override;

    size_t block_size() const override;

  private:
    DES m_des1;
    DES m_des2;
    DES m_des3;

    Bytes m_key1;
    Bytes m_key2;
    Bytes m_key3;

    TripleDESMode m_mode;

    Bytes process_block(const Bytes &block, bool encrypting) const;
    void  init_keys(const Bytes &key);
};

} // namespace crypto::des
