#include "wiener_attack.hpp"
#include "math/continued_fraction.hpp"

namespace crypto::rsa {
static WienerAttackResult try_candidate(const mpz_class &e, const mpz_class &n,
                                        const mpz_class &k,
                                        const mpz_class &d_cand) {
    if (k == 0 || d_cand <= 0) {
        return {false, 0, 0, 0};
    }

    const mpz_class ed = e * d_cand;
    if ((ed - 1) % k != 0) {
        return {false, 0, 0, 0};
    }

    const mpz_class phi = (ed - 1) / k;
    if (phi <= 0) {
        return {false, 0, 0, 0};
    }

    const mpz_class sum_pq = n - phi + 1;
    const mpz_class disc = sum_pq * sum_pq - 4 * n;
    if (disc < 0) {
        return {false, 0, 0, 0};
    }

    mpz_class sqrt_disc;
    mpz_sqrt(sqrt_disc.get_mpz_t(), disc.get_mpz_t());

    for (int delta = -2; delta <= 2; ++delta) {
        const mpz_class s = sqrt_disc + delta;
        if (s < 0) {
            continue;
        }
        if (s * s != disc) {
            continue;
        }
        if ((sum_pq + s) % 2 != 0) {
            continue;
        }

        const mpz_class p = (sum_pq + s) / 2;
        const mpz_class q = (sum_pq - s) / 2;
        if (p <= 1 || q <= 1) {
            continue;
        }
        if (p * q != n) {
            continue;
        }

        return {true, p, q, d_cand};
    }
    return {false, 0, 0, 0};
}

WienerAttackResult wiener_attack(const mpz_class &e, const mpz_class &n) {
    const auto cf = math::to_continued_fraction(e, n);

    for (const auto convs = math::convergents_from_cf(cf); const auto &[k, d_cand] : convs) {
        if (const auto result = try_candidate(e, n, k, d_cand); result.success) {
            return result;
        }
    }
    return {false, 0, 0, 0};
}
} // namespace crypto::rsa
