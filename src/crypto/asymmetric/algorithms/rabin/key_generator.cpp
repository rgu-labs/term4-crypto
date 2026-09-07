#include "key_generator.hpp"

#include <random>
#include <stdexcept>

namespace crypto::rabin {

KeyGenerator::KeyGenerator(std::unique_ptr<math::IPrimeTest> &&prime_test,
                           mp_bitcnt_t                         prime_bits,
                           double                              min_prime_probability) : m_prime_test(std::move(prime_test)),
                                                           m_prime_bits(prime_bits),
                                                           m_min_probability(min_prime_probability),
                                                           m_rng(gmp_randinit_default) {
    if (prime_bits < 8) {
        throw std::invalid_argument("prime_bits must be at least 8");
    }
    m_rng.seed(std::random_device {}());
}

mpz_class KeyGenerator::generate_prime_3_mod_4() const {
    while (true) {
        mpz_class candidate = m_rng.get_z_bits(m_prime_bits);
        mpz_setbit(candidate.get_mpz_t(), m_prime_bits - 1);
        mpz_setbit(candidate.get_mpz_t(), 0);
        mpz_setbit(candidate.get_mpz_t(), 1);
        if (mpz_sizeinbase(candidate.get_mpz_t(), 2) != m_prime_bits) {
            continue;
        }
        if (m_prime_test->is_prime(candidate, m_min_probability)) {
            return candidate;
        }
    }
}

RabinKeyPair KeyGenerator::generate() const {
    const mpz_class p = generate_prime_3_mod_4();
    mpz_class       q = generate_prime_3_mod_4();
    while (q == p) {
        q = generate_prime_3_mod_4();
    }
    RabinKeyPair kp;
    kp.public_key = {p * q};
    kp.private_key = {p, q};
    return kp;
}

} // namespace crypto::rabin
