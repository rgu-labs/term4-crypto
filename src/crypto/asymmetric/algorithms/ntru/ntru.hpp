
#pragma once

#include <gmpxx.h>
#include <optional>
#include <random>
#include <vector>

#include "crypto/internal/core/asymmetric_cipher.hpp"

namespace crypto::ntru {

struct NtruParams {
    std::size_t N = 53;
    mpz_class   p = 3;
    mpz_class   q = 547;
};

struct NtruKeyPair {
    struct PublicKey {
        NtruParams             params;
        std::vector<mpz_class> h; // coefficients of public polynomial
    };

    struct PrivateKey {
        NtruParams             params;
        std::vector<mpz_class> f;   // secret small polynomial
        std::vector<mpz_class> f_p; // f^{-1} mod p
    };

    PublicKey  public_key;
    PrivateKey private_key;
};

class KeyGenerator {
  public:
    explicit KeyGenerator(NtruParams params = NtruParams {});

    NtruKeyPair generate() const;

  private:
    std::vector<int> random_small_poly() const;

    NtruParams           m_params;
    mutable std::mt19937 m_rng;
};

class NTRUEncrypt final : public core::AsymmetricCipher {
  public:
    explicit NTRUEncrypt(NtruKeyPair::PublicKey public_key);
    explicit NTRUEncrypt(NtruKeyPair::PrivateKey private_key);
    explicit NTRUEncrypt(NtruKeyPair key_pair);

    Bytes encrypt(const Bytes &plaintext) const override;
    Bytes decrypt(const Bytes &ciphertext) const override;

  private:
    static std::vector<mpz_class> msg_poly_from_bytes(const NtruParams &params,
                                                      const Bytes      &bytes);
    static Bytes                  bytes_from_msg_poly(const NtruParams             &params,
                                                      const std::vector<mpz_class> &poly);
    static std::vector<mpz_class> poly_from_ciphertext(const NtruParams &params,
                                                       const Bytes      &bytes);
    static Bytes                  ciphertext_from_poly(const NtruParams             &params,
                                                       const std::vector<mpz_class> &poly);

    static std::vector<mpz_class> mul_mod(const std::vector<mpz_class> &a,
                                          const std::vector<mpz_class> &b,
                                          std::size_t                   N);
    static std::vector<mpz_class> poly_mod(const std::vector<mpz_class> &a,
                                           const mpz_class              &mod,
                                           std::size_t                   N);
    std::vector<int>              random_blinding() const;
    static mpz_class              centered_mod(const mpz_class &value, const mpz_class &q);

    std::optional<NtruKeyPair::PublicKey>  m_public_key;
    std::optional<NtruKeyPair::PrivateKey> m_private_key;
    mutable std::mt19937                   m_rng;
};

} // namespace crypto::ntru
