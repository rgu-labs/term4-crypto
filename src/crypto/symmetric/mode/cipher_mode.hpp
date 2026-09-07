
#pragma once

#include "internal/core/symmetric_cipher.hpp"
#include <cstddef>

namespace crypto::mode {

class SymmetricCipherMode {
  public:
    virtual ~SymmetricCipherMode() = default;

    virtual void encrypt(
        core::SymmetricCipher &cipher,
        const Bytes           &input,
        Bytes                 &output,
        size_t                 threads) = 0;

    virtual void decrypt(
        core::SymmetricCipher &cipher,
        const Bytes           &input,
        Bytes                 &output,
        size_t                 threads) = 0;
};

} // namespace crypto::mode
