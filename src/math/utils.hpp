#pragma once

#include <gmpxx.h>


namespace math {
int legendre_symbol(const mpz_class &a, const mpz_class &p);

int jacobi_symbol(const mpz_class &a, const mpz_class &n);

mpz_class gcd(const mpz_class &a, const mpz_class &b);

struct egcd_result_t {
    mpz_class gcd;
    mpz_class x;
    mpz_class y;
};

egcd_result_t egcd(const mpz_class &a, const mpz_class &b);

mpz_class powm(const mpz_class &base, const mpz_class &exp, const mpz_class &mod);

mpz_class mod_inverse(const mpz_class &a, const mpz_class &mod);

mpz_class euler_phi_definition(const mpz_class &n);

mpz_class euler_phi_factorization(const mpz_class &n);

mpz_class euler_phi_dft(const mpz_class &n);
} // namespace math
