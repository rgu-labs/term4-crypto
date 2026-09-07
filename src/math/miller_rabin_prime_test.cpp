#include "miller_rabin_prime_test.hpp"

#include <random>

#include "utils.hpp"

namespace math {
MillerRabinPrimeTest::MillerRabinPrimeTest() : m_rng(gmp_randinit_default) {
    m_rng.seed(std::random_device {}());
}

int MillerRabinPrimeTest::calculate_iterations(double min_probability) const {
    return static_cast<int>(std::ceil(std::log(1.0 / (1.0 - min_probability)) / std::log(4)));
}

bool MillerRabinPrimeTest::single_test_iteration(const mpz_class &n,
                                                 int) const {
    mpz_class   d = n - 1;
    mp_bitcnt_t s = 0;
    while (mpz_even_p(d.get_mpz_t())) {
        d >>= 1;
        ++s;
    }

    const mpz_class a = m_rng.get_z_range(n - 3) + 2;

    mpz_class x = powm(a, d, n);

    if (x == 1 || x == n - 1) {
        return true;
    }

    for (mp_bitcnt_t r = 1; r < s; ++r) {
        mpz_powm_ui(x.get_mpz_t(), x.get_mpz_t(), 2, n.get_mpz_t());
        if (x == n - 1) {
            return true;
        }
    }

    return false;
}
} // namespace math
