#pragma once

#include <cstdint>
#include <iosfwd>

namespace math::gf2n {

class Gf2nPolynomial {
  public:
    static constexpr unsigned MAX_DEGREE = 32;

    Gf2nPolynomial() = default;

    explicit Gf2nPolynomial(uint64_t bits) : m_bits(bits) {}

    static Gf2nPolynomial monomial(unsigned degree);

    static Gf2nPolynomial zero() { return Gf2nPolynomial(0); }
    static Gf2nPolynomial one() { return Gf2nPolynomial(1); }

    uint64_t bits() const { return m_bits; }
    bool     is_zero() const { return m_bits == 0; }
    bool     is_one() const { return m_bits == 1; }

    unsigned degree() const;

    Gf2nPolynomial  operator^(const Gf2nPolynomial &other) const;
    Gf2nPolynomial &operator^=(const Gf2nPolynomial &other);

    bool operator==(const Gf2nPolynomial &other) const { return m_bits == other.m_bits; }
    bool operator!=(const Gf2nPolynomial &other) const { return m_bits != other.m_bits; }

    Gf2nPolynomial divided_by(const Gf2nPolynomial &divisor, Gf2nPolynomial &remainder) const;
    Gf2nPolynomial mod(const Gf2nPolynomial &modulus) const;

    static Gf2nPolynomial mul_mod(const Gf2nPolynomial &a, const Gf2nPolynomial &b,
                                  const Gf2nPolynomial &modulus);

    static Gf2nPolynomial inverse(const Gf2nPolynomial &a,
                                  const Gf2nPolynomial &modulus);

    static Gf2nPolynomial gcd(const Gf2nPolynomial &a, const Gf2nPolynomial &b);

    static bool is_irreducible(const Gf2nPolynomial &p);

    static Gf2nPolynomial pow_mod(const Gf2nPolynomial &base, uint64_t exponent,
                                  const Gf2nPolynomial &modulus);

  private:
    uint64_t m_bits = 0;
};

std::ostream &operator<<(std::ostream &os, const Gf2nPolynomial &p);

} // namespace math::gf2n
