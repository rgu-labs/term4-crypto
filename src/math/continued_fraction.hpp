#pragma once

#include <gmpxx.h>
#include <vector>

namespace math {
struct Fraction {
    mpz_class num;
    mpz_class den;
};

std::vector<mpz_class> to_continued_fraction(const mpz_class &a,
                                             const mpz_class &b);

Fraction from_continued_fraction(const std::vector<mpz_class> &cf);

std::vector<Fraction> convergents_from_cf(const std::vector<mpz_class> &cf);

std::vector<Fraction> convergents(const mpz_class &a, const mpz_class &b);

std::vector<int> calkin_wilf_path(const mpz_class &a, const mpz_class &b);

std::vector<int> stern_brocot_path(const mpz_class &a, const mpz_class &b);

Fraction calkin_wilf_from_path(const std::vector<int> &path);

Fraction stern_brocot_from_path(const std::vector<int> &path);

std::vector<Fraction>
convergents_by_stern_brocot_path(const std::vector<int> &path);
} // namespace math
