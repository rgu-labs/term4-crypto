
#pragma once
#include "prime_test.hpp"

namespace math {
class FermatPrimeTest : public PrimeTest {
  public:
    FermatPrimeTest();

  protected:
    bool single_test_iteration(const mpz_class &n, int iteration_index) const override;

  private:
    mutable gmp_randclass m_rng;
};
} // namespace math
