#include <gtest/gtest.h>

#include <memory>

#include "crypto/asymmetric/algorithms/elgamal/elgamal.hpp"
#include "math/miller_rabin_prime_test.hpp"

using namespace crypto;

static crypto::elgamal::ElGamalKeyPair make_keypair(mp_bitcnt_t bits = 28) {
    return crypto::elgamal::KeyGenerator(
               std::make_unique<math::MillerRabinPrimeTest>(), bits, 0.9999)
        .generate();
}

class ElGamalSignTest : public ::testing::Test {
  protected:
    void SetUp() override {
        kp = make_keypair(28);
        signer = std::make_unique<elgamal::ElGamalSigner>(kp);
        verifier = std::make_unique<elgamal::ElGamalVerifier>(kp.public_key);
    }
    elgamal::ElGamalKeyPair                   kp;
    std::unique_ptr<elgamal::ElGamalSigner>   signer;
    std::unique_ptr<elgamal::ElGamalVerifier> verifier;
};

TEST_F(ElGamalSignTest, ValidSignaturePasses) {
    const Bytes msg = {'H', 'e', 'l', 'l', 'o', '!'};
    const auto  sig = signer->sign(msg);
    ASSERT_TRUE(verifier->verify(sig, msg));
}

TEST_F(ElGamalSignTest, ArbitraryLengthMessagePasses) {
    Bytes msg;
    for (unsigned i = 0; i < 4096; ++i) {
        msg.push_back(static_cast<uint8_t>(i & 0xFF));
    }
    const auto sig = signer->sign(msg);
    ASSERT_TRUE(verifier->verify(sig, msg));
}

TEST_F(ElGamalSignTest, EmptyMessagePasses) {
    const auto sig = signer->sign(Bytes {});
    ASSERT_TRUE(verifier->verify(sig, Bytes {}));
}

TEST_F(ElGamalSignTest, TamperedMessageFails) {
    const Bytes msg = {1, 2, 3, 4};
    const auto  sig = signer->sign(msg);
    Bytes       tampered = msg;
    tampered[tampered.size() - 1] ^= 0x01;
    ASSERT_FALSE(verifier->verify(sig, tampered));
}

TEST_F(ElGamalSignTest, TamperedRPartFails) {
    const Bytes msg = {0xDE, 0xAD, 0xBE, 0xEF};
    auto        sig = signer->sign(msg);
    auto        orig = sig;
    do {
        sig.r += 1;
    } while (sig.r == orig.r);
    ASSERT_FALSE(verifier->verify(sig, msg));
}

TEST_F(ElGamalSignTest, TamperedSPartFails) {
    const Bytes msg = {0x11, 0x22, 0x33};
    auto        sig = signer->sign(msg);
    auto        orig = sig;
    do {
        sig.s += 1;
    } while (sig.s == orig.s);
    ASSERT_FALSE(verifier->verify(sig, msg));
}

TEST_F(ElGamalSignTest, WrongPublicKeyFails) {
    const auto               kp2 = make_keypair(28);
    const Bytes              msg = {0x42};
    const auto               sig = signer->sign(msg);
    elgamal::ElGamalVerifier other_verifier(kp2.public_key);
    ASSERT_FALSE(other_verifier.verify(sig, msg));
}

TEST_F(ElGamalSignTest, SignatureHasTwoParts) {
    const auto sig = signer->sign(Bytes {0x01});
    ASSERT_TRUE(sig.r > 0);
    ASSERT_TRUE(sig.s >= 0);
}

TEST_F(ElGamalSignTest, SignatureIsRandomized) {
    const Bytes msg = {0x07};
    const auto  s1 = signer->sign(msg);
    const auto  s2 = signer->sign(msg);
    ASSERT_TRUE((s1.r != s2.r) || (s1.s != s2.s));
    ASSERT_TRUE(verifier->verify(s1, msg));
    ASSERT_TRUE(verifier->verify(s2, msg));
}

TEST_F(ElGamalSignTest, OutOfRangeRPartFails) {
    const Bytes               msg = {0x01};
    const auto                sig = signer->sign(msg);
    elgamal::ElGamalSignature bad {sig.r + kp.public_key.p, sig.s};
    ASSERT_FALSE(verifier->verify(bad, msg));
}

TEST_F(ElGamalSignTest, NegativeSPartFails) {
    const Bytes               msg = {0x01};
    elgamal::ElGamalSignature bad {1, -1};
    ASSERT_FALSE(verifier->verify(bad, msg));
}
