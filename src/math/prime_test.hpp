#pragma once

#include <cmath>
#include <gmpxx.h>

namespace math {
class IPrimeTest {
  public:
    virtual ~IPrimeTest() = default;

    virtual bool is_prime(const mpz_class &n, double min_probability) = 0;
};

class PrimeTest : public IPrimeTest {
  public:
    bool is_prime(const mpz_class &n, double min_probability) final;

  protected:
    virtual int calculate_iterations(double min_probability) const;

    virtual bool single_test_iteration(const mpz_class &n, int iteration_index) const = 0;
};
} // namespace math
