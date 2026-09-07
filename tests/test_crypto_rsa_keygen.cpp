#include "math/miller_rabin_prime_test.hpp"
#include <gtest/gtest.h>

#include "asymmetric/algorithms/rsa/key_generator.hpp"

static crypto::rsa::KeyPair make_keypair(mp_bitcnt_t bits = 512) {
    const auto gen = crypto::rsa::KeyGenerator(
        std::make_unique<math::MillerRabinPrimeTest>(),
        bits,
        0.9999);
    return gen.generate();
}

TEST(RsaKeyGeneratorTest, PublicExponentIsOdd) {
    const auto kp = make_keypair();
    ASSERT_TRUE(kp.public_key.e % 2 == 1);
}

TEST(RsaKeyGeneratorTest, PublicExponentGreaterThanOne) {
    const auto kp = make_keypair();
    ASSERT_GT(kp.public_key.e, mpz_class(1));
}

TEST(RsaKeyGeneratorTest, ModulusIsLargeEnough) {
    const auto kp = make_keypair(512);
    ASSERT_GE(mpz_sizeinbase(kp.public_key.n.get_mpz_t(), 2), static_cast<size_t>(1000));
}

TEST(RsaKeyGeneratorTest, PublicAndPrivateModulusMatch) {
    const auto kp = make_keypair();
    ASSERT_EQ(kp.public_key.n, kp.private_key.n);
}

TEST(RsaKeyGeneratorTest, EncryptThenDecryptGivesOriginal) {
    const auto      kp = make_keypair();
    const mpz_class m(42);
    mpz_class       c, recovered;
    mpz_powm(c.get_mpz_t(), m.get_mpz_t(), kp.public_key.e.get_mpz_t(), kp.public_key.n.get_mpz_t());
    mpz_powm(recovered.get_mpz_t(), c.get_mpz_t(), kp.private_key.d.get_mpz_t(), kp.private_key.n.get_mpz_t());
    ASSERT_EQ(recovered, m);
}

TEST(RsaKeyGeneratorTest, EncryptThenDecryptLargeMessage) {
    const auto      kp = make_keypair();
    const mpz_class m("123456789012345678901234567890");
    mpz_class       c, recovered;
    mpz_powm(c.get_mpz_t(), m.get_mpz_t(), kp.public_key.e.get_mpz_t(), kp.public_key.n.get_mpz_t());
    mpz_powm(recovered.get_mpz_t(), c.get_mpz_t(), kp.private_key.d.get_mpz_t(), kp.private_key.n.get_mpz_t());
    ASSERT_EQ(recovered, m);
}

TEST(RsaKeyGeneratorTest, EDProductCongruentOneModPhi) {
    const auto      kp = make_keypair();
    const mpz_class ed = kp.public_key.e * kp.private_key.d;
    mpz_class       m(12345);
    mpz_class       result;
    mpz_powm(result.get_mpz_t(), m.get_mpz_t(), ed.get_mpz_t(), kp.public_key.n.get_mpz_t());
    ASSERT_EQ(result, m);
}

TEST(RsaKeyGeneratorTest, TwoKeyPairsHaveDifferentModuli) {
    const auto kp1 = make_keypair();
    const auto kp2 = make_keypair();
    ASSERT_NE(kp1.public_key.n, kp2.public_key.n);
}

TEST(RsaKeyGeneratorTest, TwoKeyPairsHaveDifferentPrivateKeys) {
    const auto kp1 = make_keypair();
    const auto kp2 = make_keypair();
    ASSERT_NE(kp1.private_key.d, kp2.private_key.d);
}

TEST(RsaKeyGeneratorTest, WienerProtectionDGreaterThanNFourthRoot) {
    const auto kp = make_keypair();
    mpz_class  n_root;
    mpz_root(n_root.get_mpz_t(), kp.public_key.n.get_mpz_t(), 4);
    ASSERT_GT(kp.private_key.d, n_root);
}

TEST(RsaKeyGeneratorTest, InvalidBitSizeThrows) {
    ASSERT_THROW(
        crypto::rsa::KeyGenerator(std::make_unique<math::MillerRabinPrimeTest>(), 128, 0.9999),
        std::invalid_argument);
}

TEST(RsaKeyGeneratorTest, InvalidProbabilityThrows) {
    const auto gen = crypto::rsa::KeyGenerator(
        std::make_unique<math::MillerRabinPrimeTest>(),
        512,
        0.9999);
    (void)gen;
    math::MillerRabinPrimeTest test;
    ASSERT_THROW(test.is_prime(mpz_class(7), 0.3), std::invalid_argument);
}
