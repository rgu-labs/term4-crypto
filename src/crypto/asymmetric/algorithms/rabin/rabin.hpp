#pragma once

#include <optional>

#include "crypto/internal/core/asymmetric_cipher.hpp"
#include "key_generator.hpp"

namespace crypto::rabin {

class Rabin final : public core::AsymmetricCipher {
  public:
    explicit Rabin(RabinKeyPair::PublicKey public_key);
    explicit Rabin(RabinKeyPair::PrivateKey private_key);
    explicit Rabin(RabinKeyPair key_pair);

    Bytes encrypt(const Bytes &plaintext) const override;
    Bytes decrypt(const Bytes &ciphertext) const override;

  private:
    static mpz_class              bytes_to_mpz(const Bytes &bytes);
    static Bytes                  mpz_to_bytes_fixed(const mpz_class &value, size_t size);
    static mpz_class              encode_block(const mpz_class &payload, const mpz_class &n,
                                               unsigned long redundancy_bytes);
    static Bytes                  encode_padded(const Bytes &data, const mpz_class &n);
    bool                          decode_padded(const Bytes &data, const mpz_class &n,
                                                Bytes &out) const;
    static std::vector<mpz_class> crt_roots(const mpz_class &m1,
                                            const mpz_class &m2,
                                            const mpz_class &p,
                                            const mpz_class &q);

    std::optional<RabinKeyPair::PublicKey>  m_public_key;
    std::optional<RabinKeyPair::PrivateKey> m_private_key;
};

} // namespace crypto::rabin
