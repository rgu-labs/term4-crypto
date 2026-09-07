#pragma once

#include <gmpxx.h>
#include <memory>

#include "crypto/asymmetric/algorithms/rsa/key_generator.hpp"
#include "math/prime_test.hpp"

namespace crypto::rsa {
class VulnerableKeyGenerator {
  public:
    enum class Vulnerability {
        Fermat,
        Wiener,
    };

    VulnerableKeyGenerator(std::unique_ptr<math::IPrimeTest> &&prime_test,
                           mp_bitcnt_t                         prime_bits,
                           double                              min_prime_probability,
                           Vulnerability                       vulnerability);

    KeyPair generate() const;

  private:
    KeyPair generate_fermat_vulnerable() const;
    KeyPair generate_wiener_vulnerable() const;

    mpz_class generate_prime() const;
    mpz_class generate_close_prime(const mpz_class &p) const;
    mpz_class generate_small_d_pair(mpz_class &out_p, mpz_class &out_q) const;

    static mpz_class choose_public_exponent(const mpz_class &phi_n);

    std::unique_ptr<math::IPrimeTest> m_prime_test;
    mp_bitcnt_t                       m_prime_bits;
    double                            m_min_probability;
    Vulnerability                     m_vulnerability;
    mutable gmp_randclass             m_rng;
};
} // namespace crypto::rsa
