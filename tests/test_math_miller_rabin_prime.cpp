#include "math/miller_rabin_prime_test.hpp"
#include <gtest/gtest.h>

TEST(MillerRabinPrimeTest, SmallPrimesAreDetected) {
    math::MillerRabinPrimeTest test;
    ASSERT_TRUE(test.is_prime(mpz_class(2), 0.99));
    ASSERT_TRUE(test.is_prime(mpz_class(3), 0.99));
    ASSERT_TRUE(test.is_prime(mpz_class(5), 0.99));
    ASSERT_TRUE(test.is_prime(mpz_class(7), 0.99));
    ASSERT_TRUE(test.is_prime(mpz_class(13), 0.99));
}

TEST(MillerRabinPrimeTest, SmallCompositesAreRejected) {
    math::MillerRabinPrimeTest test;
    ASSERT_FALSE(test.is_prime(mpz_class(4), 0.99));
    ASSERT_FALSE(test.is_prime(mpz_class(6), 0.99));
    ASSERT_FALSE(test.is_prime(mpz_class(8), 0.99));
    ASSERT_FALSE(test.is_prime(mpz_class(9), 0.99));
    ASSERT_FALSE(test.is_prime(mpz_class(15), 0.99));
}

TEST(MillerRabinPrimeTest, LargePrime) {
    math::MillerRabinPrimeTest test;
    ASSERT_TRUE(test.is_prime(mpz_class(7919), 0.99));
}

TEST(MillerRabinPrimeTest, LargeComposite) {
    math::MillerRabinPrimeTest test;
    ASSERT_FALSE(test.is_prime(mpz_class(8000), 0.99));
}

TEST(MillerRabinPrimeTest, OneIsNotPrime) {
    math::MillerRabinPrimeTest test;
    ASSERT_FALSE(test.is_prime(mpz_class(1), 0.99));
}

TEST(MillerRabinPrimeTest, TwoIsPrime) {
    math::MillerRabinPrimeTest test;
    ASSERT_TRUE(test.is_prime(mpz_class(2), 0.99));
}

TEST(MillerRabinPrimeTest, EdgeCases) {
    math::MillerRabinPrimeTest test;
    ASSERT_FALSE(test.is_prime(mpz_class(0), 0.99));
    ASSERT_FALSE(test.is_prime(mpz_class(-7), 0.99));
}

TEST(MillerRabinPrimeTest, BigNumber) {
    math::MillerRabinPrimeTest test;
    const mpz_class            prime("8412804295548816281158770604568724917439306435151683818674705563848111243427426441834264469262656667");
    ASSERT_TRUE(test.is_prime(prime, 0.99));
}

TEST(MillerRabinPrimeTest, CarmichaelNumbersAreRejected) {
    math::MillerRabinPrimeTest test;
    ASSERT_FALSE(test.is_prime(mpz_class(561), 0.99));
    ASSERT_FALSE(test.is_prime(mpz_class(1105), 0.99));
    ASSERT_FALSE(test.is_prime(mpz_class(1729), 0.99));
    ASSERT_FALSE(test.is_prime(mpz_class(2465), 0.99));
    ASSERT_FALSE(test.is_prime(mpz_class(8911), 0.99));
}
