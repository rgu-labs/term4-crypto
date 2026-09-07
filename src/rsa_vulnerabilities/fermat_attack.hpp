
#pragma once

#include <gmpxx.h>

namespace crypto::rsa {
struct FermatAttackResult {
    bool      success;
    mpz_class p;
    mpz_class q;
};

FermatAttackResult fermat_attack(
    const mpz_class &n,
    unsigned long    max_steps = std::numeric_limits<unsigned long>::max());
} // namespace crypto::rsa
