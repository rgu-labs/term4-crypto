#include "key_generator.hpp"

#include <random>
#include <stdexcept>

#include "math/utils.hpp"

namespace crypto::rsa {
KeyGenerator::KeyGenerator(std::unique_ptr<math::IPrimeTest> &&prime_test,
                           mp_bitcnt_t                         prime_bits,
                           double                              min_prime_probability) : m_prime_test(std::move(prime_test)),
                                                           m_prime_bits(prime_bits),
                                                           m_min_probability(min_prime_probability),
                                                           m_rng(gmp_randinit_default) {
    if (prime_bits < 512) {
        throw std::invalid_argument("prime_bits must be at least 512");
    }
    m_rng.seed(std::random_device {}());
}

mpz_class KeyGenerator::generate_prime() const {
    while (true) {
        mpz_class candidate = m_rng.get_z_bits(m_prime_bits);
        mpz_setbit(candidate.get_mpz_t(), m_prime_bits - 1);
        mpz_setbit(candidate.get_mpz_t(), 0);
        if (m_prime_test->is_prime(candidate, m_min_probability)) {
            return candidate;
        }
    }
}

mpz_class KeyGenerator::generate_q_for(const mpz_class &p) const {
    mpz_class threshold;
    mpz_ui_pow_ui(threshold.get_mpz_t(), 2, m_prime_bits / 2 - 1);
    while (true) {
        mpz_class candidate = m_rng.get_z_bits(m_prime_bits);
        mpz_setbit(candidate.get_mpz_t(), m_prime_bits - 1);
        mpz_class diff = candidate > p ? candidate - p : p - candidate;
        if (diff <= threshold) {
            continue;
        }
        mpz_class r = candidate % 6;
        if (r == 0) {
            candidate += 1;
        } else if (r == 2) {
            candidate += 5;
        } else if (r == 3) {
            candidate += 4;
        } else if (r == 4) {
            candidate += 3;
        }
        static constexpr int k_max_walk = 100;
        for (int i = 0; i < k_max_walk; ++i) {
            diff = candidate > p ? candidate - p : p - candidate;
            if (diff > threshold && candidate != p) {
                if (m_prime_test->is_prime(candidate, m_min_probability)) {
                    return candidate;
                }
            }
            const mpz_class step = (candidate % 6 == 1) ? mpz_class(4) : mpz_class(2);
            candidate += step;
            if (mpz_sizeinbase(candidate.get_mpz_t(), 2) > m_prime_bits + 1) {
                break;
            }
        }
    }
}

bool KeyGenerator::is_wiener_safe(const mpz_class &d, const mpz_class &n) {
    mpz_class n_root;
    mpz_root(n_root.get_mpz_t(), n.get_mpz_t(), 4);
    return d > n_root;
}

mpz_class KeyGenerator::choose_public_exponent(const mpz_class &phi_n) {
    static const unsigned long candidates[] = {65537, 257, 17, 5, 3};
    for (const unsigned long e_val : candidates) {
        mpz_class e(e_val);
        if (e < phi_n && math::gcd(e, phi_n) == 1) {
            return e;
        }
    }
    mpz_class e(65537);
    while (e < phi_n) {
        if (math::gcd(e, phi_n) == 1) {
            return e;
        }
        e += 2;
    }
    throw std::runtime_error("Failed to find a suitable public exponent");
}

KeyPair KeyGenerator::generate() const {
    while (true) {
        const mpz_class p = generate_prime();
        const mpz_class q = generate_q_for(p);
        const mpz_class n = p * q;
        const mpz_class phi_n = (p - 1) * (q - 1);
        const mpz_class e = choose_public_exponent(phi_n);
        const mpz_class d = math::mod_inverse(e, phi_n);

        if (mpz_sizeinbase(n.get_mpz_t(), 2) != m_prime_bits * 2) {
            continue;
        }

        if (!is_wiener_safe(d, n)) {
            continue;
        }

        KeyPair kp;
        kp.public_key = {n, e};
        kp.private_key = {
            .n = n,
            .e = e,
            .d = d,
            .p = p,
            .q = q,
            .dp = d % (p - 1),
            .dq = d % (q - 1),
            .qp = math::mod_inverse(q, p),
        };
        return kp;
    }
}
} // namespace crypto::rsa
