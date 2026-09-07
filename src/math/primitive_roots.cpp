#include "primitive_roots.hpp"

#include "utils.hpp"

namespace math {

static bool has_primitive_roots(const mpz_class &n) {
    if (n == 2 || n == 4) {
        return true;
    }

    mpz_class tmp = n;
    if (tmp % 2 == 0) {
        tmp /= 2;
    }
    if (tmp % 2 == 0) {
        return false;
    }

    mpz_class p = 1;
    for (mpz_class d = 3; d * d <= tmp; d += 2) {
        if (tmp % d == 0) {
            p = d;
            while (tmp % d == 0) {
                tmp /= d;
            }
            break;
        }
    }
    if (tmp > 1) {
        p = tmp;
    }

    if (p == 1) {
        return false;
    }

    mpz_class remainder = n;
    if (remainder % 2 == 0) {
        remainder /= 2;
    }
    while (remainder % p == 0) {
        remainder /= p;
    }

    return remainder == 1;
}

static bool is_primitive_root(const mpz_class &g, const mpz_class &n, const mpz_class &phi_n) {
    if (gcd(g, n) != 1) {
        return false;
    }

    std::vector<mpz_class> factors;
    mpz_class              tmp = phi_n;
    for (mpz_class d = 2; d * d <= tmp; ++d) {
        if (tmp % d == 0) {
            factors.push_back(d);
            while (tmp % d == 0) {
                tmp /= d;
            }
        }
    }
    if (tmp > 1) {
        factors.push_back(tmp);
    }


    for (const auto &factor : factors) {
        if (powm(g, phi_n / factor, n) == 1) {
            return false;
        }
    }
    return true;
}

std::vector<mpz_class> primitive_roots(const mpz_class &n) {
    if (n < 2) {
        return {};
    }
    if (!has_primitive_roots(n)) {
        return {};
    }

    const mpz_class phi_n = euler_phi_factorization(n);
    const mpz_class phi_phi_n = euler_phi_factorization(phi_n);

    mpz_class first_root = -1;
    for (mpz_class g = 1; g < n; ++g) {
        if (is_primitive_root(g, n, phi_n)) {
            first_root = g;
            break;
        }
    }

    if (first_root == -1) {
        return {};
    }

    std::vector<mpz_class> result;
    result.reserve(phi_phi_n.get_ui());

    for (mpz_class i = 1; i <= phi_n; ++i) {
        if (gcd(i, phi_n) == 1) {
            result.push_back(powm(first_root, i, n));
        }
    }

    std::ranges::sort(result);
    return result;
}

} // namespace math
