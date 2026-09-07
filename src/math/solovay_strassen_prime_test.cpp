#include "solovay_strassen_prime_test.hpp"

#include <random>

#include "utils.hpp"

namespace math {
SolovayStrassenPrimeTest::SolovayStrassenPrimeTest() : m_rng(gmp_randinit_default) {
    m_rng.seed(std::random_device {}());
}

bool SolovayStrassenPrimeTest::single_test_iteration(const mpz_class &n,
                                                     int) const {
    if (mpz_even_p(n.get_mpz_t())) {
        return false;
    }

    const mpz_class a = m_rng.get_z_range(n - 3) + 2;

    if (math::gcd(a, n) != 1) {
        return false;
    }

    const int jacobi = math::jacobi_symbol(a, n);

    const mpz_class exp = (n - 1) / 2;
    const mpz_class x = math::powm(a, exp, n);

    const mpz_class jacobi_mod_n = (jacobi == -1) ? (n - 1) : mpz_class(jacobi);

    return x == jacobi_mod_n;
}
} // namespace math
