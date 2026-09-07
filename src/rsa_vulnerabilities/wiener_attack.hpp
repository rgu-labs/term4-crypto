#pragma once

#include <gmpxx.h>

namespace crypto::rsa {

struct WienerAttackResult {
    bool      success;
    mpz_class p;
    mpz_class q;
    mpz_class d;
};

WienerAttackResult wiener_attack(const mpz_class &e, const mpz_class &n);

} // namespace crypto::rsa
