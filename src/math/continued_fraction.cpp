#include "continued_fraction.hpp"
#include "utils.hpp"
#include <stdexcept>

namespace math {

std::vector<mpz_class> to_continued_fraction(const mpz_class &a,
                                             const mpz_class &b) {
    if (b <= 0) {
        throw std::invalid_argument("to_continued_fraction: b must be positive");
    }
    std::vector<mpz_class> result;
    mpz_class              a_cur = a, b_cur = b;
    while (b_cur != 0) {
        mpz_class q, r;
        mpz_fdiv_qr(q.get_mpz_t(), r.get_mpz_t(), a_cur.get_mpz_t(),
                    b_cur.get_mpz_t());
        result.push_back(q);
        a_cur = b_cur;
        b_cur = r;
    }
    return result;
}

Fraction from_continued_fraction(const std::vector<mpz_class> &cf) {
    if (cf.empty()) {
        throw std::invalid_argument("from_continued_fraction: cf is empty");
    }
    mpz_class num(1), den(0);
    for (int i = static_cast<int>(cf.size()) - 1; i >= 0; --i) {
        mpz_class new_num = cf[i] * num + den;
        den = num;
        num = new_num;
    }
    mpz_class g = gcd(abs(num), abs(den));
    return {num / g, den / g};
}

std::vector<Fraction> convergents_from_cf(const std::vector<mpz_class> &cf) {
    if (cf.empty()) {
        throw std::invalid_argument("convergents_from_cf: cf is empty");
    }
    std::vector<Fraction> result;
    mpz_class             p_prev(1), p_curr = cf[0];
    mpz_class             q_prev(0), q_curr(1);
    result.push_back({p_curr, q_curr});
    for (size_t i = 1; i < cf.size(); ++i) {
        mpz_class p_next = cf[i] * p_curr + p_prev;
        mpz_class q_next = cf[i] * q_curr + q_prev;
        result.push_back({p_next, q_next});
        p_prev = p_curr;
        p_curr = p_next;
        q_prev = q_curr;
        q_curr = q_next;
    }
    return result;
}

std::vector<Fraction> convergents(const mpz_class &a, const mpz_class &b) {
    return convergents_from_cf(to_continued_fraction(a, b));
}

std::vector<int> calkin_wilf_path(const mpz_class &a, const mpz_class &b) {
    if (a <= 0 || b <= 0) {
        throw std::invalid_argument("calkin_wilf_path: a and b must be positive");
    }
    if (gcd(a, b) != 1) {
        throw std::invalid_argument("calkin_wilf_path: a and b must be coprime");
    }
    std::vector<int> path;
    mpz_class        a_cur = a, b_cur = b;
    while (a_cur != 1 || b_cur != 1) {
        if (a_cur < b_cur) {
            path.push_back(1);
            b_cur -= a_cur;
        } else {
            path.push_back(0);
            a_cur -= b_cur;
        }
    }
    std::ranges::reverse(path);
    return path;
}

std::vector<int> stern_brocot_path(const mpz_class &a, const mpz_class &b) {
    if (a <= 0 || b <= 0) {
        throw std::invalid_argument("stern_brocot_path: a and b must be positive");
    }
    if (math::gcd(a, b) != 1) {
        throw std::invalid_argument("stern_brocot_path: a and b must be coprime");
    }
    std::vector<int> path;
    mpz_class        lo_n(0), lo_d(1);
    mpz_class        hi_n(1), hi_d(0);
    while (true) {
        mpz_class mid_n = lo_n + hi_n;
        mpz_class mid_d = lo_d + hi_d;
        if (a == mid_n && b == mid_d) {
            break;
        }
        if (a * mid_d < b * mid_n) {
            path.push_back(0);
            hi_n = mid_n;
            hi_d = mid_d;
        } else {
            path.push_back(1);
            lo_n = mid_n;
            lo_d = mid_d;
        }
    }
    return path;
}

Fraction calkin_wilf_from_path(const std::vector<int> &path) {
    mpz_class a(1), b(1);
    for (int step : path) {
        if (step == 0) {
            a = a + b;
        } else {
            b = a + b;
        }
    }
    return {a, b};
}

Fraction stern_brocot_from_path(const std::vector<int> &path) {
    mpz_class lo_n(0), lo_d(1);
    mpz_class hi_n(1), hi_d(0);
    for (int step : path) {
        mpz_class mid_n = lo_n + hi_n;
        mpz_class mid_d = lo_d + hi_d;
        if (step == 0) {
            hi_n = mid_n;
            hi_d = mid_d;
        } else {
            lo_n = mid_n;
            lo_d = mid_d;
        }
    }
    return {lo_n + hi_n, lo_d + hi_d};
}

std::vector<Fraction>
convergents_by_stern_brocot_path(const std::vector<int> &path) {
    std::vector<Fraction> result;
    mpz_class             lo_n(0), lo_d(1);
    mpz_class             hi_n(1), hi_d(0);
    for (const int step : path) {
        mpz_class mid_n = lo_n + hi_n;
        mpz_class mid_d = lo_d + hi_d;
        result.push_back({mid_n, mid_d});
        if (step == 0) {
            hi_n = mid_n;
            hi_d = mid_d;
        } else {
            lo_n = mid_n;
            lo_d = mid_d;
        }
    }
    result.push_back({lo_n + hi_n, lo_d + hi_d});
    return result;
}

} // namespace math
