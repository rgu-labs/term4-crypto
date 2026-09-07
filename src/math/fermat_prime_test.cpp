#include "fermat_prime_test.hpp"

#include <random>

#include "utils.hpp"

namespace math {
FermatPrimeTest::FermatPrimeTest() : m_rng(gmp_randinit_default) {
    m_rng.seed(std::random_device {}());
}

bool FermatPrimeTest::single_test_iteration(const mpz_class &n, int iteration_index) const {

    const mpz_class a = m_rng.get_z_range(n - 3) + 2;

    const mpz_class result = math::powm(a, n - 1, n);
    return result == 1;
}
} // namespace math
