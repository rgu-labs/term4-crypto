#include <gtest/gtest.h>
#include <sstream>

#include "math/gf2n/gf2n_polynomial.hpp"

using math::gf2n::Gf2nPolynomial;

static unsigned degree_of(uint64_t bits) {
    return Gf2nPolynomial(bits).degree();
}

static bool reducible_by_brute_force(uint64_t p) {
    if (p == 0) {
        return true;
    }
    const unsigned n = degree_of(p);
    if (n < 1) {
        return true;
    }
    for (uint64_t q = 2; q < (1ULL << n); ++q) {
        if (degree_of(q) < 1) {
            continue;
        }
        if (Gf2nPolynomial(p).mod(Gf2nPolynomial(q)) == Gf2nPolynomial::zero()) {
            return true;
        }
    }
    return false;
}

TEST(Gf2nPolynomial, ConstructionAndDegree) {
    EXPECT_EQ(Gf2nPolynomial(0x11B).degree(), 8u);
    EXPECT_EQ(Gf2nPolynomial(0b101).degree(), 2u);
    EXPECT_EQ(Gf2nPolynomial(0b1).degree(), 0u);
    EXPECT_EQ(Gf2nPolynomial(0).degree(), 0u);
    EXPECT_TRUE(Gf2nPolynomial(0).is_zero());
    EXPECT_TRUE(Gf2nPolynomial(1).is_one());
    EXPECT_FALSE(Gf2nPolynomial(0).is_one());
    EXPECT_EQ(Gf2nPolynomial::monomial(3).bits(), 8u);
    EXPECT_EQ(Gf2nPolynomial::monomial(0), Gf2nPolynomial::one());
    EXPECT_THROW(Gf2nPolynomial::monomial(Gf2nPolynomial::MAX_DEGREE + 1),
                 std::invalid_argument);
}

TEST(Gf2nPolynomial, AdditionIsXor) {
    EXPECT_EQ((Gf2nPolynomial(0b1010) ^ Gf2nPolynomial(0b1100)).bits(), 0b0110);
    EXPECT_EQ((Gf2nPolynomial(0xFF) ^ Gf2nPolynomial(0xFF)).bits(), 0);
    Gf2nPolynomial a(0b10101);
    a ^= Gf2nPolynomial(0b01111);
    EXPECT_EQ(a.bits(), 0b11010u);
}

TEST(Gf2nPolynomial, Division) {
    Gf2nPolynomial quotient;
    Gf2nPolynomial remainder;
    quotient = Gf2nPolynomial(0x1B).divided_by(Gf2nPolynomial(0x03), remainder);
    EXPECT_EQ(quotient.bits(), 0x09);
    EXPECT_TRUE(remainder.is_zero());

    quotient = Gf2nPolynomial(0x13).divided_by(Gf2nPolynomial(0x03), remainder);
    EXPECT_EQ(quotient.bits(), 0x0E);
    EXPECT_EQ(remainder.bits(), 0x01);

    quotient = Gf2nPolynomial(0x05).divided_by(Gf2nPolynomial(0x02), remainder);
    EXPECT_EQ(quotient.bits(), 0x02);
    EXPECT_EQ(remainder.bits(), 0x01);

    EXPECT_THROW(Gf2nPolynomial(0x05).divided_by(Gf2nPolynomial(0), remainder),
                 std::invalid_argument);
}

TEST(Gf2nPolynomial, MultiplicationModulo) {
    EXPECT_EQ(Gf2nPolynomial::mul_mod(Gf2nPolynomial(9), Gf2nPolynomial(5),
                                      Gf2nPolynomial(0x13))
                  .bits(),
              0x0B);
    EXPECT_EQ(Gf2nPolynomial::mul_mod(Gf2nPolynomial(0x02), Gf2nPolynomial(0x8D),
                                      Gf2nPolynomial(0x11B))
                  .bits(),
              0x01);
    EXPECT_TRUE(Gf2nPolynomial::mul_mod(Gf2nPolynomial(0), Gf2nPolynomial(0x42),
                                        Gf2nPolynomial(0x11B))
                    .is_zero());
    EXPECT_TRUE(Gf2nPolynomial::mul_mod(Gf2nPolynomial(0x42), Gf2nPolynomial(0),
                                        Gf2nPolynomial(0x11B))
                    .is_zero());
    EXPECT_THROW(Gf2nPolynomial::mul_mod(Gf2nPolynomial(0x01), Gf2nPolynomial(0x02),
                                         Gf2nPolynomial(0)),
                 std::invalid_argument);
}

TEST(Gf2nPolynomial, InverseModulo) {
    EXPECT_EQ(Gf2nPolynomial::inverse(Gf2nPolynomial(0x8D), Gf2nPolynomial(0x11B))
                  .bits(),
              0x02);
    EXPECT_EQ(Gf2nPolynomial::inverse(Gf2nPolynomial(0x53), Gf2nPolynomial(0x11B))
                  .bits(),
              0xCA);
    EXPECT_TRUE(
        Gf2nPolynomial::inverse(Gf2nPolynomial(0), Gf2nPolynomial(0x11B)).is_zero());
    EXPECT_TRUE(
        Gf2nPolynomial::inverse(Gf2nPolynomial(0x01), Gf2nPolynomial(0)).is_zero());
    EXPECT_THROW(Gf2nPolynomial::inverse(Gf2nPolynomial(0b11), Gf2nPolynomial(0b101)),
                 std::invalid_argument);
}

TEST(Gf2nPolynomial, InversePropertyInGf256) {
    for (uint64_t a = 1; a < 256; ++a) {
        Gf2nPolynomial inv = Gf2nPolynomial::inverse(
            Gf2nPolynomial(a), Gf2nPolynomial(0x11B));
        Gf2nPolynomial product = Gf2nPolynomial::mul_mod(
            Gf2nPolynomial(a), inv, Gf2nPolynomial(0x11B));
        EXPECT_EQ(product.bits(), 1u);
    }
}

TEST(Gf2nPolynomial, Gcd) {
    EXPECT_EQ(Gf2nPolynomial::gcd(Gf2nPolynomial(0x1B), Gf2nPolynomial(0x03))
                  .bits(),
              0x03);
    EXPECT_EQ(Gf2nPolynomial::gcd(Gf2nPolynomial(0x13), Gf2nPolynomial(0x05))
                  .bits(),
              0x01);
    EXPECT_EQ(Gf2nPolynomial::gcd(Gf2nPolynomial(0), Gf2nPolynomial(0x07)).bits(),
              0x07);
}

TEST(Gf2nPolynomial, PowMod) {
    EXPECT_EQ(Gf2nPolynomial::pow_mod(Gf2nPolynomial(0b10), 4, Gf2nPolynomial(0x13))
                  .bits(),
              0b11);
    EXPECT_EQ(Gf2nPolynomial::pow_mod(Gf2nPolynomial(0x02), 8, Gf2nPolynomial(0x11B))
                  .bits(),
              0x1B);
}

TEST(Gf2nPolynomial, IrreducibilityKnown) {
    EXPECT_TRUE(Gf2nPolynomial::is_irreducible(Gf2nPolynomial(0x02)));
    EXPECT_TRUE(Gf2nPolynomial::is_irreducible(Gf2nPolynomial(0x03)));
    EXPECT_TRUE(Gf2nPolynomial::is_irreducible(Gf2nPolynomial(0x13)));
    EXPECT_TRUE(Gf2nPolynomial::is_irreducible(Gf2nPolynomial(0x11B)));
    EXPECT_TRUE(Gf2nPolynomial::is_irreducible(Gf2nPolynomial(0x11D)));

    EXPECT_FALSE(Gf2nPolynomial::is_irreducible(Gf2nPolynomial(0)));
    EXPECT_FALSE(Gf2nPolynomial::is_irreducible(Gf2nPolynomial(0x05)));
    EXPECT_FALSE(Gf2nPolynomial::is_irreducible(Gf2nPolynomial(0x1B)));
    EXPECT_FALSE(Gf2nPolynomial::is_irreducible(Gf2nPolynomial(0x09)));
}

TEST(Gf2nPolynomial, IrreducibilityMatchesBruteForce) {
    for (uint64_t deg = 1; deg <= 6; ++deg) {
        uint64_t start = 1ULL << deg;
        uint64_t end = 1ULL << (deg + 1);
        for (uint64_t p = start; p < end; ++p) {
            bool expected = !reducible_by_brute_force(p);
            EXPECT_EQ(Gf2nPolynomial::is_irreducible(Gf2nPolynomial(p)), expected)
                << "polynomial 0x" << std::hex << p << " degree " << deg;
        }
    }
}

TEST(Gf2nPolynomial, StreamOutput) {
    std::stringstream ss;
    ss << Gf2nPolynomial(0x11B);
    EXPECT_EQ(ss.str(), "x^8 + x^4 + x^3 + x + 1");

    std::stringstream sz;
    sz << Gf2nPolynomial(0);
    EXPECT_EQ(sz.str(), "0");

    std::stringstream so;
    so << Gf2nPolynomial(0b1000);
    EXPECT_EQ(so.str(), "x^3");

    std::stringstream sw;
    sw << Gf2nPolynomial(0b0001);
    EXPECT_EQ(sw.str(), "1");
}
