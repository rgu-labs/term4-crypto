
#pragma once

#include <optional>

#include "crypto/internal/core/asymmetric_cipher.hpp"
#include "key_generator.hpp"

namespace crypto::rsa {

class Rsa final : public core::AsymmetricCipher {
  public:
    explicit Rsa(KeyPair::PublicKey public_key);
    explicit Rsa(KeyPair::PrivateKey private_key);
    explicit Rsa(KeyPair key_pair);

    Bytes encrypt(const Bytes &plaintext) const override;
    Bytes decrypt(const Bytes &ciphertext) const override;

  private:
    static mpz_class bytes_to_mpz(const Bytes &bytes);
    static Bytes     mpz_to_bytes(const mpz_class &value, size_t target_size);

    std::optional<KeyPair::PublicKey>  m_public_key;
    std::optional<KeyPair::PrivateKey> m_private_key;
};

} // namespace crypto::rsa
