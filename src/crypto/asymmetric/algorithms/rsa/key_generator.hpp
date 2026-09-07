
#pragma once

#include <gmpxx.h>
#include <memory>

#include "math/prime_test.hpp"

namespace crypto::rsa {

struct KeyPair {
    struct PublicKey {
        mpz_class n;
        mpz_class e;
    };

    struct PrivateKey {
        mpz_class n;  // modulus
        mpz_class e;  // publicExponent
        mpz_class d;  // privateExponent
        mpz_class p;  // prime1
        mpz_class q;  // prime2
        mpz_class dp; // d mod (p-1)
        mpz_class dq; // d mod (q-1)
        mpz_class qp; // q^-1 mod p
    };

    PublicKey  public_key;
    PrivateKey private_key;
};

class KeyGenerator {
  public:
    KeyGenerator(std::unique_ptr<math::IPrimeTest> &&prime_test,
                 mp_bitcnt_t                         prime_bits,
                 double                              min_prime_probability);

    KeyPair generate() const;

  private:
    mpz_class        generate_prime() const;
    mpz_class        generate_q_for(const mpz_class &p) const;
    static mpz_class choose_public_exponent(const mpz_class &phi_n);
    static bool      is_wiener_safe(const mpz_class &d, const mpz_class &n);

    std::unique_ptr<math::IPrimeTest> m_prime_test;
    mp_bitcnt_t                       m_prime_bits;
    double                            m_min_probability;
    mutable gmp_randclass             m_rng;
};

} // namespace crypto::rsa
