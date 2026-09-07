
#include "prime_test.hpp"

namespace math {
bool PrimeTest::is_prime(const mpz_class &n, double min_probability) {
    if (min_probability < 0.5 || min_probability > 1.0) {
        throw std::invalid_argument("Invalid prime test proba");
    }
    if (n < 2) {
        return false;
    }
    if (n == 2) {
        return true;
    }
    if (n == 3) {
        return true;
    }

    const int iterations = calculate_iterations(min_probability);

    for (int i = 0; i < iterations; ++i) {
        if (!single_test_iteration(n, i)) {
            return false;
        }
    }

    return true;
}

int PrimeTest::calculate_iterations(double min_probability) const {
    return static_cast<int>(std::ceil(std::log(1.0 / (1.0 - min_probability)) / std::log(2)));
}
} // namespace math
