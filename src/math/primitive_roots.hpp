#pragma once

#include <vector>
#include <gmpxx.h>

namespace math {

std::vector<mpz_class> primitive_roots(const mpz_class &n);

} // namespace math
