#include "utils.hpp"

#include <cmath>

namespace math {
int legendre_symbol(const mpz_class &a, const mpz_class &p) {
    const mpz_class a_mod = a % p;
    if (a_mod == 0) {
        return 0;
    }
    const mpz_class result = powm(a_mod, (p - 1) / 2, p);
    if (result == 1) {
        return 1;
    }
    return -1;
}

int jacobi_symbol(const mpz_class &a, const mpz_class &n) {
    if (n <= 0 || n % 2 == 0) {
        throw std::invalid_argument("n must be a positive odd integer");
    }
    mpz_class a_cur = a % n;
    if (a_cur < 0) {
        a_cur += n;
    }
    mpz_class n_cur = n;
    int       result = 1;
    while (a_cur != 0) {
        while (a_cur % 2 == 0) {
            a_cur /= 2;
            if (const mpz_class n_mod8 = n_cur % 8; n_mod8 == 3 || n_mod8 == 5) {
                result = -result;
            }
        }
        std::swap(a_cur, n_cur);
        if (a_cur % 4 == 3 && n_cur % 4 == 3) {
            result = -result;
        }
        a_cur = a_cur % n_cur;
    }
    if (n_cur == 1) {
        return result;
    }
    return 0;
}

mpz_class gcd(const mpz_class &a, const mpz_class &b) {
    const auto result = egcd(a, b);
    return abs(result.gcd);
}

egcd_result_t egcd(const mpz_class &a, const mpz_class &b) {
    mpz_class old_r = a, r = b;
    mpz_class old_s(1), s(0);
    mpz_class old_t(0), t(1);
    while (r != 0) {
        mpz_class q, new_r;
        mpz_tdiv_qr(q.get_mpz_t(), new_r.get_mpz_t(), old_r.get_mpz_t(), r.get_mpz_t());
        old_r = r;
        r = new_r;
        const mpz_class new_s = old_s - q * s;
        old_s = s;
        s = new_s;
        const mpz_class new_t = old_t - q * t;
        old_t = t;
        t = new_t;
    }
    return {old_r, old_s, old_t};
}

mpz_class powm(const mpz_class &base, const mpz_class &exp, const mpz_class &mod) {
    if (mod == 1) {
        return 0;
    }
    mpz_class result(1);
    mpz_class b = base % mod;
    mpz_class e = exp;
    while (e > 0) {
        if (e % 2 == 1) {
            result = (result * b) % mod;
        }
        e /= 2;
        b = (b * b) % mod;
    }
    return result;
}

mpz_class mod_inverse(const mpz_class &a, const mpz_class &mod) {
    const auto [g, x, y] = egcd(a, mod);
    if (g != 1) {
        throw std::invalid_argument("mod_inverse: a and mod are not coprime");
    }
    return ((x % mod) + mod) % mod;
}

mpz_class euler_phi_definition(const mpz_class &n) {
    if (n <= 0) {
        throw std::invalid_argument("euler_phi_definition: n must be positive");
    }
    if (n == 1) {
        return 1;
    }
    mpz_class count(0);
    for (mpz_class k(1); k < n; ++k) {
        if (gcd(k, n) == 1) {
            ++count;
        }
    }
    return count;
}

mpz_class euler_phi_factorization(const mpz_class &n) {
    if (n <= 0) {
        throw std::invalid_argument("euler_phi_factorization: n must be positive");
    }
    if (n == 1) {
        return 1;
    }
    mpz_class result = n;
    mpz_class temp = n;
    for (mpz_class i(2); i * i <= temp; ++i) {
        if (temp % i == 0) {
            result -= result / i;
            while (temp % i == 0) {
                temp /= i;
            }
        }
    }
    if (temp > 1) {
        result -= result / temp;
    }
    return result;
}

mpz_class euler_phi_dft(const mpz_class &n) {
    if (n <= 0) {
        throw std::invalid_argument("euler_phi_dft: n must be positive");
    }
    if (n == 1) {
        return 1;
    }
    double result = 0.0;
    for (mpz_class k(1); k <= n; ++k) {
        const mpz_class g = gcd(k, n);
        const double    angle = 2.0 * M_PI * mpz_get_d(k.get_mpz_t()) / mpz_get_d(n.get_mpz_t());
        result += mpz_get_d(g.get_mpz_t()) * std::cos(angle);
    }
    return static_cast<long>(std::round(result));
}
} // namespace math
