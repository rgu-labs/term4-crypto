#pragma once

#include <gmpxx.h>
#include <memory>

#include "math/prime_test.hpp"

namespace crypto::rabin {

struct RabinKeyPair {
    struct PublicKey {
        mpz_class n;
    };

    struct PrivateKey {
        mpz_class p;
        mpz_class q;
    };

    PublicKey  public_key;
    PrivateKey private_key;
};

class KeyGenerator {
  public:
    KeyGenerator(std::unique_ptr<math::IPrimeTest> &&prime_test,
                 mp_bitcnt_t                         prime_bits,
                 double                              min_prime_probability);

    RabinKeyPair generate() const;

  private:
    mpz_class generate_prime_3_mod_4() const;

    std::unique_ptr<math::IPrimeTest> m_prime_test;
    mp_bitcnt_t                       m_prime_bits;
    double                            m_min_probability;
    mutable gmp_randclass             m_rng;
};

} // namespace crypto::rabin
