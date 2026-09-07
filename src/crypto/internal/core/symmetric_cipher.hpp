#pragma once

#include "crypto/internal/bytes.hpp"

namespace crypto::core {

class SymmetricCipher {
  public:
    virtual ~SymmetricCipher() = default;

    virtual void set_encryption_key(const Bytes &) = 0;
    virtual void set_decryption_key(const Bytes &) = 0;

    virtual Bytes encrypt_block(const Bytes &) const = 0;
    virtual Bytes decrypt_block(const Bytes &) const = 0;

    virtual size_t block_size() const = 0;
};
} // namespace crypto::core
