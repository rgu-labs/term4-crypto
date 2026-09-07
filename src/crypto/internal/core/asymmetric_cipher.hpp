
#pragma once

#include "../bytes.hpp"

namespace crypto::core {

class AsymmetricCipher {
  public:
    virtual ~AsymmetricCipher() = default;

    virtual Bytes encrypt(const Bytes &plaintext) const = 0;
    virtual Bytes decrypt(const Bytes &ciphertext) const = 0;
};

} // namespace crypto::core
