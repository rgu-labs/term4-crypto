#include "vulnerable_key_generator.hpp"

#include <stdexcept>

#include "math/utils.hpp"
#include <random>

namespace crypto::rsa {
VulnerableKeyGenerator::VulnerableKeyGenerator(
    std::unique_ptr<math::IPrimeTest> &&prime_test,
    mp_bitcnt_t                         prime_bits,
    double                              min_prime_probability,
    Vulnerability                       vulnerability) : m_prime_test(std::move(prime_test)),
                                   m_prime_bits(prime_bits),
                                   m_min_probability(min_prime_probability),
                                   m_vulnerability(vulnerability),
                                   m_rng(gmp_randinit_default) {
    if (prime_bits < 512) {
        throw std::invalid_argument("prime_bits must be at least 512");
    }
    m_rng.seed(std::random_device {}());
}

KeyPair VulnerableKeyGenerator::generate() const {
    switch (m_vulnerability) {
        case Vulnerability::Fermat:
            return generate_fermat_vulnerable();
        case Vulnerability::Wiener:
            return generate_wiener_vulnerable();
    }
    throw std::logic_error("unknown vulnerability type");
}

mpz_class VulnerableKeyGenerator::generate_prime() const {
    while (true) {
        mpz_class candidate = m_rng.get_z_bits(m_prime_bits);
        mpz_setbit(candidate.get_mpz_t(), m_prime_bits - 1);
        mpz_setbit(candidate.get_mpz_t(), 0);
        if (m_prime_test->is_prime(candidate, m_min_probability)) {
            return candidate;
        }
    }
}

mpz_class VulnerableKeyGenerator::generate_close_prime(const mpz_class &p) const {
    mpz_class n_approx;
    mpz_mul(n_approx.get_mpz_t(), p.get_mpz_t(), p.get_mpz_t());

    mpz_class threshold;
    mpz_root(threshold.get_mpz_t(), n_approx.get_mpz_t(), 4);
    threshold /= 2;
    if (threshold < 2) {
        threshold = 2;
    }

    while (true) {
        mpz_class offset = m_rng.get_z_range(threshold * 2);
        offset -= threshold;
        if (offset % 2 == 0) {
            offset += 1;
        }

        mpz_class candidate = p + offset;
        if (candidate <= 1) {
            continue;
        }
        if (candidate == p) {
            continue;
        }

        mpz_setbit(candidate.get_mpz_t(), 0);

        if (m_prime_test->is_prime(candidate, m_min_probability)) {
            return candidate;
        }
    }
}

mpz_class VulnerableKeyGenerator::generate_small_d_pair(
    mpz_class &out_p, mpz_class &out_q) const {
    while (true) {
        out_p = generate_prime();
        out_q = generate_prime();
        if (out_p == out_q) {
            continue;
        }

        const mpz_class n = out_p * out_q;
        const mpz_class phi_n = (out_p - 1) * (out_q - 1);

        mpz_class n_root4;
        mpz_root(n_root4.get_mpz_t(), n.get_mpz_t(), 4);
        mpz_class d_bound = n_root4 / 3;
        if (d_bound < 3) {
            continue;
        }

        mpz_class range = d_bound - 3;
        if (range < 1) {
            continue;
        }
        mpz_class d = m_rng.get_z_range(range) + 3;
        mpz_setbit(d.get_mpz_t(), 0);

        if (math::gcd(d, phi_n) != 1) {
            continue;
        }

        const mpz_class e = math::mod_inverse(d, phi_n);

        if (e <= 1 || e >= phi_n) {
            continue;
        }

        return e;
    }
}

KeyPair VulnerableKeyGenerator::generate_fermat_vulnerable() const {
    while (true) {
        const mpz_class p = generate_prime();
        const mpz_class q = generate_close_prime(p);

        const mpz_class n = p * q;
        const mpz_class phi_n = (p - 1) * (q - 1);
        const mpz_class e = choose_public_exponent(phi_n);
        const mpz_class d = math::mod_inverse(e, phi_n);

        if (mpz_sizeinbase(n.get_mpz_t(), 2) < m_prime_bits * 2 - 2) {
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

KeyPair VulnerableKeyGenerator::generate_wiener_vulnerable() const {
    mpz_class       p, q;
    const mpz_class e = generate_small_d_pair(p, q);

    const mpz_class n = p * q;
    const mpz_class phi_n = (p - 1) * (q - 1);
    const mpz_class d = math::mod_inverse(e, phi_n);

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

mpz_class VulnerableKeyGenerator::choose_public_exponent(const mpz_class &phi_n) {
    static const unsigned long candidates[] = {65537, 257, 17, 5, 3};
    for (const unsigned long e_val : candidates) {
        if (mpz_class e(e_val); e < phi_n && math::gcd(e, phi_n) == 1) {
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
    throw std::runtime_error("failed to find a suitable public exponent");
}
} // namespace crypto::rsa
