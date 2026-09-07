#include <gtest/gtest.h>
#include "math/utils.hpp"

TEST(LegendreSymbol, ZeroReturnsZero) {
    ASSERT_EQ(math::legendre_symbol(mpz_class(0), mpz_class(7)), 0);
}

TEST(LegendreSymbol, QuadraticResidue) {
    ASSERT_EQ(math::legendre_symbol(mpz_class(2), mpz_class(7)), 1);
}

TEST(LegendreSymbol, QuadraticNonResidue) {
    ASSERT_EQ(math::legendre_symbol(mpz_class(3), mpz_class(7)), -1);
}

TEST(LegendreSymbol, MultipleOfP) {
    ASSERT_EQ(math::legendre_symbol(mpz_class(14), mpz_class(7)), 0);
}

TEST(LegendreSymbol, OneIsAlwaysResidue) {
    ASSERT_EQ(math::legendre_symbol(mpz_class(1), mpz_class(11)), 1);
    ASSERT_EQ(math::legendre_symbol(mpz_class(1), mpz_class(13)), 1);
    ASSERT_EQ(math::legendre_symbol(mpz_class(1), mpz_class(17)), 1);
}

TEST(LegendreSymbol, LargePrime) {
    ASSERT_EQ(math::legendre_symbol(mpz_class(2), mpz_class(17)), 1);
}

TEST(JacobiSymbol, InvalidEvenNThrows) {
    ASSERT_THROW(math::jacobi_symbol(mpz_class(1), mpz_class(4)), std::invalid_argument);
}

TEST(JacobiSymbol, InvalidNonPositiveNThrows) {
    ASSERT_THROW(math::jacobi_symbol(mpz_class(1), mpz_class(0)), std::invalid_argument);
    ASSERT_THROW(math::jacobi_symbol(mpz_class(1), mpz_class(-1)), std::invalid_argument);
}

TEST(JacobiSymbol, ZeroReturnsZero) {
    ASSERT_EQ(math::jacobi_symbol(mpz_class(0), mpz_class(9)), 0);
}

TEST(JacobiSymbol, OneReturnsOne) {
    ASSERT_EQ(math::jacobi_symbol(mpz_class(1), mpz_class(9)), 1);
}

TEST(JacobiSymbol, MatchesLegendreForPrime) {
    ASSERT_EQ(math::jacobi_symbol(mpz_class(2), mpz_class(7)), 1);
    ASSERT_EQ(math::jacobi_symbol(mpz_class(3), mpz_class(7)), -1);
}

TEST(JacobiSymbol, CompositeN) {
    ASSERT_EQ(math::jacobi_symbol(mpz_class(2), mpz_class(9)), 1);
}

TEST(JacobiSymbol, NegativeA) {
    ASSERT_EQ(math::jacobi_symbol(mpz_class(-1), mpz_class(15)), -1);
}

TEST(Gcd, BothZero) {
    ASSERT_EQ(math::gcd(mpz_class(0), mpz_class(0)), mpz_class(0));
}

TEST(Gcd, OneZero) {
    ASSERT_EQ(math::gcd(mpz_class(5), mpz_class(0)), mpz_class(5));
    ASSERT_EQ(math::gcd(mpz_class(0), mpz_class(7)), mpz_class(7));
}

TEST(Gcd, Coprime) {
    ASSERT_EQ(math::gcd(mpz_class(7), mpz_class(13)), mpz_class(1));
}

TEST(Gcd, CommonDivisor) {
    ASSERT_EQ(math::gcd(mpz_class(12), mpz_class(8)), mpz_class(4));
}

TEST(Gcd, SameNumbers) {
    ASSERT_EQ(math::gcd(mpz_class(6), mpz_class(6)), mpz_class(6));
}

TEST(Gcd, NegativeInputs) {
    ASSERT_EQ(math::gcd(mpz_class(-12), mpz_class(8)), mpz_class(4));
    ASSERT_EQ(math::gcd(mpz_class(12), mpz_class(-8)), mpz_class(4));
}

TEST(Gcd, Commutative) {
    ASSERT_EQ(math::gcd(mpz_class(48), mpz_class(18)), mpz_class(6));
    ASSERT_EQ(math::gcd(mpz_class(18), mpz_class(48)), mpz_class(6));
}

TEST(Egcd, Basic) {
    auto res = math::egcd(mpz_class(35), mpz_class(15));
    ASSERT_EQ(res.gcd, mpz_class(5));
    ASSERT_EQ(res.x, mpz_class(1));
    ASSERT_EQ(res.y, mpz_class(-2));
}

TEST(Egcd, Coprime) {
    auto res = math::egcd(mpz_class(7), mpz_class(13));
    ASSERT_EQ(res.gcd, mpz_class(1));
    ASSERT_EQ(res.x, mpz_class(2));
    ASSERT_EQ(res.y, mpz_class(-1));
}

TEST(Egcd, OneZero) {
    auto res = math::egcd(mpz_class(5), mpz_class(0));
    ASSERT_EQ(res.gcd, mpz_class(5));
    ASSERT_EQ(res.x, mpz_class(1));
    ASSERT_EQ(res.y, mpz_class(0));
}

TEST(Egcd, LargeNumbers) {
    auto res = math::egcd(mpz_class(1234567890), mpz_class(987654321));
    ASSERT_EQ(res.gcd, mpz_class(9));
    ASSERT_EQ(res.x, mpz_class(21947873));
    ASSERT_EQ(res.y, mpz_class(-27434841));
}

TEST(Powm, BaseZero) {
    ASSERT_EQ(math::powm(mpz_class(0), mpz_class(5), mpz_class(7)), mpz_class(0));
}

TEST(Powm, ExpZero) {
    ASSERT_EQ(math::powm(mpz_class(5), mpz_class(0), mpz_class(7)), mpz_class(1));
}

TEST(Powm, ExpOne) {
    ASSERT_EQ(math::powm(mpz_class(5), mpz_class(1), mpz_class(7)), mpz_class(5));
}

TEST(Powm, BasicCase) {
    ASSERT_EQ(math::powm(mpz_class(2), mpz_class(10), mpz_class(1000)), mpz_class(24));
}

TEST(Powm, FermatLittleTheorem) {
    ASSERT_EQ(math::powm(mpz_class(3), mpz_class(6), mpz_class(7)), mpz_class(1));
}

TEST(Powm, ModOneAlwaysZero) {
    ASSERT_EQ(math::powm(mpz_class(123), mpz_class(456), mpz_class(1)), mpz_class(0));
}

TEST(Powm, LargeBase) {
    ASSERT_EQ(math::powm(mpz_class(123456789), mpz_class(2), mpz_class(1000000007)), mpz_class(643499475));
}

TEST(ModInverse, BasicCase) {
    ASSERT_EQ(math::mod_inverse(mpz_class(3), mpz_class(7)), mpz_class(5));
}

TEST(ModInverse, VerifyResult) {
    ASSERT_EQ(math::mod_inverse(mpz_class(17), mpz_class(31)), mpz_class(11));
}

TEST(ModInverse, NotCoprimeThrows) {
    ASSERT_THROW(math::mod_inverse(mpz_class(4), mpz_class(8)), std::invalid_argument);
}

TEST(ModInverse, OneAlwaysOne) {
    ASSERT_EQ(math::mod_inverse(mpz_class(1), mpz_class(7)), mpz_class(1));
}

TEST(ModInverse, ResultInRange) {
    ASSERT_EQ(math::mod_inverse(mpz_class(3), mpz_class(11)), mpz_class(4));
}

TEST(EulerPhiDefinition, One) {
    ASSERT_EQ(math::euler_phi_definition(mpz_class(1)), mpz_class(1));
}

TEST(EulerPhiDefinition, Two) {
    ASSERT_EQ(math::euler_phi_definition(mpz_class(2)), mpz_class(1));
}

TEST(EulerPhiDefinition, Prime) {
    ASSERT_EQ(math::euler_phi_definition(mpz_class(7)), mpz_class(6));
    ASSERT_EQ(math::euler_phi_definition(mpz_class(13)), mpz_class(12));
}

TEST(EulerPhiDefinition, PrimePower) {
    ASSERT_EQ(math::euler_phi_definition(mpz_class(8)), mpz_class(4));
}

TEST(EulerPhiDefinition, Composite) {
    ASSERT_EQ(math::euler_phi_definition(mpz_class(12)), mpz_class(4));
}

TEST(EulerPhiFactorization, MatchesDefinitionUpTo50) {
    for (long n = 1; n <= 50; ++n) {
        ASSERT_EQ(math::euler_phi_factorization(mpz_class(n)),
                  math::euler_phi_definition(mpz_class(n)))
            << "n = " << n;
    }
}

TEST(EulerPhiFactorization, LargePrime) {
    ASSERT_EQ(math::euler_phi_factorization(mpz_class(9973)), mpz_class(9972));
}

TEST(EulerPhiFactorization, PowerOfTwo) {
    ASSERT_EQ(math::euler_phi_factorization(mpz_class(64)), mpz_class(32));
}

TEST(EulerPhiDft, MatchesDefinitionUpTo20) {
    for (long n = 1; n <= 20; ++n) {
        ASSERT_EQ(math::euler_phi_dft(mpz_class(n)),
                  math::euler_phi_definition(mpz_class(n)))
            << "n = " << n;
    }
}

TEST(EulerPhiDft, Prime) {
    ASSERT_EQ(math::euler_phi_dft(mpz_class(11)), mpz_class(10));
}

TEST(EulerPhiDft, Composite) {
    ASSERT_EQ(math::euler_phi_dft(mpz_class(12)), mpz_class(4));
}
