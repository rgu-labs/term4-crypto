#pragma once

#include <gmpxx.h>

namespace crypto::dh {

struct DhParams {
    mpz_class p;
    mpz_class g;
};

} // namespace crypto::dh
