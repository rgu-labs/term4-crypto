#include "gf2n_polynomial.hpp"

#include <ostream>
#include <stdexcept>
#include <vector>

namespace math::gf2n {

Gf2nPolynomial Gf2nPolynomial::monomial(unsigned degree) {
    if (degree > MAX_DEGREE) {
        throw std::invalid_argument("Gf2nPolynomial: degree exceeds MAX_DEGREE");
    }
    return Gf2nPolynomial(1ULL << degree);
}

unsigned Gf2nPolynomial::degree() const {
    if (m_bits == 0) {
        return 0;
    }
    return static_cast<unsigned>(63 - __builtin_clzll(m_bits));
}

Gf2nPolynomial Gf2nPolynomial::operator^(const Gf2nPolynomial &other) const {
    return Gf2nPolynomial(m_bits ^ other.m_bits);
}

Gf2nPolynomial &Gf2nPolynomial::operator^=(const Gf2nPolynomial &other) {
    m_bits ^= other.m_bits;
    return *this;
}

Gf2nPolynomial Gf2nPolynomial::divided_by(const Gf2nPolynomial &divisor,
                                          Gf2nPolynomial       &remainder) const {
    if (divisor.is_zero()) {
        throw std::invalid_argument("Gf2nPolynomial: division by zero polynomial");
    }
    const unsigned deg_div = divisor.degree();
    uint64_t       quotient = 0;
    uint64_t       rem = m_bits;
    while (rem != 0) {
        const auto deg_rem = static_cast<unsigned>(63 - __builtin_clzll(rem));
        if (deg_rem < deg_div) {
            break;
        }
        const unsigned shift = deg_rem - deg_div;
        quotient |= 1ULL << shift;
        rem ^= divisor.m_bits << shift;
    }
    remainder = Gf2nPolynomial(rem);
    return Gf2nPolynomial(quotient);
}

Gf2nPolynomial Gf2nPolynomial::mod(const Gf2nPolynomial &modulus) const {
    Gf2nPolynomial remainder;
    divided_by(modulus, remainder);
    return remainder;
}

Gf2nPolynomial Gf2nPolynomial::mul_mod(const Gf2nPolynomial &a,
                                       const Gf2nPolynomial &b,
                                       const Gf2nPolynomial &modulus) {
    if (modulus.is_zero()) {
        throw std::invalid_argument("Gf2nPolynomial::mul_mod: zero modulus");
    }
    const unsigned n = modulus.degree();
    const uint64_t mod_bits = modulus.m_bits;

    uint64_t result = 0;
    uint64_t acc = a.m_bits;
    uint64_t multiplier = b.m_bits;
    while (multiplier != 0) {
        if (multiplier & 1ULL) {
            result ^= acc;
        }
        multiplier >>= 1;
        if (acc & (1ULL << (n - 1))) {
            acc = (acc << 1) ^ mod_bits;
        } else {
            acc <<= 1;
        }
    }
    return Gf2nPolynomial(result);
}

Gf2nPolynomial Gf2nPolynomial::inverse(const Gf2nPolynomial &a,
                                       const Gf2nPolynomial &modulus) {
    if (modulus.is_zero() || a.is_zero()) {
        return Gf2nPolynomial::zero();
    }
    Gf2nPolynomial r0 = modulus;
    Gf2nPolynomial r1 = a;
    Gf2nPolynomial t0 = Gf2nPolynomial::zero();
    Gf2nPolynomial t1 = Gf2nPolynomial::one();

    while (!r1.is_zero()) {
        Gf2nPolynomial remainder;
        Gf2nPolynomial quotient = r0.divided_by(r1, remainder);
        Gf2nPolynomial t = t0 ^ mul_mod(quotient, t1, modulus);
        r0 = r1;
        r1 = remainder;
        t0 = t1;
        t1 = t;
    }
    if (!r0.is_one()) {
        throw std::invalid_argument(
            "Gf2nPolynomial::inverse: polynomial is not invertible mod given modulus");
    }
    return t0;
}

Gf2nPolynomial Gf2nPolynomial::gcd(const Gf2nPolynomial &a,
                                   const Gf2nPolynomial &b) {
    Gf2nPolynomial r0 = a;
    Gf2nPolynomial r1 = b;
    while (!r1.is_zero()) {
        Gf2nPolynomial remainder;
        r0.divided_by(r1, remainder);
        r0 = r1;
        r1 = remainder;
    }
    return r0;
}

namespace {
bool is_prime_unsigned(unsigned value) {
    if (value < 2) {
        return false;
    }
    for (unsigned d = 2; d * d <= value; ++d) {
        if (value % d == 0) {
            return false;
        }
    }
    return true;
}
} // namespace

bool Gf2nPolynomial::is_irreducible(const Gf2nPolynomial &p) {
    if (p.is_zero()) {
        return false;
    }
    const unsigned n = p.degree();
    if (n < 1) {
        return false;
    }
    if (n == 1) {
        return true;
    }
    if ((p.m_bits & 1ULL) == 0) {
        return false;
    }

    const Gf2nPolynomial x = Gf2nPolynomial::monomial(1);

    std::vector<unsigned> targets;
    for (unsigned d = 2; d <= n; ++d) {
        if (is_prime_unsigned(d) && n % d == 0) {
            targets.push_back(n / d);
        }
    }

    Gf2nPolynomial powered = x.mod(p);
    Gf2nPolynomial x_mod = x.mod(p);

    bool                        final_congruent = false;
    std::vector<Gf2nPolynomial> sampled;
    for (unsigned k = 1; k <= n; ++k) {
        powered = mul_mod(powered, powered, p);
        if (k == n) {
            final_congruent = (powered == x_mod);
        }
        for (unsigned target : targets) {
            if (k == target) {
                sampled.push_back(powered);
            }
        }
    }

    if (!final_congruent) {
        return false;
    }
    for (const Gf2nPolynomial &sample : sampled) {
        if (!gcd(sample ^ x_mod, p).is_one()) {
            return false;
        }
    }
    return true;
}

Gf2nPolynomial Gf2nPolynomial::pow_mod(const Gf2nPolynomial &base,
                                       uint64_t              exponent,
                                       const Gf2nPolynomial &modulus) {
    Gf2nPolynomial result = Gf2nPolynomial::one();
    Gf2nPolynomial factor = base;
    while (exponent != 0) {
        if (exponent & 1ULL) {
            result = mul_mod(result, factor, modulus);
        }
        factor = mul_mod(factor, factor, modulus);
        exponent >>= 1;
    }
    return result;
}

std::ostream &operator<<(std::ostream &os, const Gf2nPolynomial &p) {
    if (p.is_zero()) {
        os << "0";
        return os;
    }
    bool           first = true;
    const unsigned n = p.degree();
    for (unsigned d = n + 1; d-- > 0;) {
        if ((p.bits() & (1ULL << d)) == 0) {
            continue;
        }
        if (!first) {
            os << " + ";
        }
        first = false;
        if (d == 0) {
            os << "1";
        } else if (d == 1) {
            os << "x";
        } else {
            os << "x^" << d;
        }
    }
    return os;
}

} // namespace math::gf2n
