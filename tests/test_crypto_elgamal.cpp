#include <gtest/gtest.h>

#include <memory>

#include "crypto/asymmetric/algorithms/elgamal/elgamal.hpp"
#include "math/miller_rabin_prime_test.hpp"

using namespace crypto;

static crypto::elgamal::ElGamalKeyPair make_keypair(mp_bitcnt_t bits = 24) {
    return crypto::elgamal::KeyGenerator(
               std::make_unique<math::MillerRabinPrimeTest>(), bits, 0.9999)
        .generate();
}

class ElGamalTest : public ::testing::Test {
  protected:
    void SetUp() override {
        kp = make_keypair(24);
    }
    crypto::elgamal::ElGamalKeyPair kp;
};

TEST_F(ElGamalTest, EncryptDecryptSingleByte) {
    crypto::elgamal::ElGamal elg(kp);
    const Bytes              msg = {0x42};
    const Bytes              enc = elg.encrypt(msg);
    const Bytes              dec = elg.decrypt(enc);
    ASSERT_EQ(dec, msg);
}

TEST_F(ElGamalTest, EncryptDecryptMultipleBytes) {
    auto                     kp32 = make_keypair(32);
    crypto::elgamal::ElGamal elg(kp32);
    const Bytes              msg = {0x01, 0x02, 0x03, 0x04};
    const Bytes              enc = elg.encrypt(msg);
    const Bytes              dec = elg.decrypt(enc);
    ASSERT_EQ(dec, msg);
}

TEST_F(ElGamalTest, EncryptedDiffersFromPlaintext) {
    crypto::elgamal::ElGamal elg(kp);
    const Bytes              msg = {0x07};
    const Bytes              enc = elg.encrypt(msg);
    ASSERT_NE(enc, msg);
}

TEST_F(ElGamalTest, CiphertextIsTwoModulusParts) {
    const size_t part_size =
        (mpz_sizeinbase(kp.public_key.p.get_mpz_t(), 2) + 7) / 8;
    crypto::elgamal::ElGamal elg(kp);
    const Bytes              enc = elg.encrypt(Bytes {0x05});
    ASSERT_EQ(enc.size(), 2 * part_size);
}

TEST_F(ElGamalTest, RandomizedEncryptionDifferentEachTime) {
    crypto::elgamal::ElGamal elg(kp);
    const Bytes              msg = {0x09};
    const Bytes              enc1 = elg.encrypt(msg);
    const Bytes              enc2 = elg.encrypt(msg);
    ASSERT_NE(enc1, enc2);
    ASSERT_EQ(elg.decrypt(enc1), msg);
    ASSERT_EQ(elg.decrypt(enc2), msg);
}

TEST_F(ElGamalTest, PubOnlyCanEncrypt) {
    crypto::elgamal::ElGamal elg(kp.public_key);
    ASSERT_NO_THROW(elg.encrypt(Bytes {0x2A}));
}

TEST_F(ElGamalTest, PubOnlyCannotDecrypt) {
    crypto::elgamal::ElGamal elg(kp.public_key);
    const Bytes              enc = crypto::elgamal::ElGamal(kp).encrypt(Bytes {0x2A});
    ASSERT_THROW(elg.decrypt(enc), std::logic_error);
}

TEST_F(ElGamalTest, PrivOnlyCanDecrypt) {
    const Bytes              enc = crypto::elgamal::ElGamal(kp).encrypt(Bytes {0x2A});
    crypto::elgamal::ElGamal elg(kp.private_key);
    ASSERT_NO_THROW(elg.decrypt(enc));
}

TEST_F(ElGamalTest, PrivOnlyCannotEncrypt) {
    crypto::elgamal::ElGamal elg(kp.private_key);
    ASSERT_THROW(elg.encrypt(Bytes {0x2A}), std::logic_error);
}

TEST_F(ElGamalTest, EncryptWithPubDecryptWithPriv) {
    auto        kp48 = make_keypair(48);
    const Bytes msg = {0xDE, 0xAD, 0xBE, 0xEF};
    const Bytes enc = crypto::elgamal::ElGamal(kp48.public_key).encrypt(msg);
    const Bytes dec = crypto::elgamal::ElGamal(kp48.private_key).decrypt(enc);
    ASSERT_EQ(dec, msg);
}

TEST_F(ElGamalTest, WrongPrivateKeyFailsDecrypt) {
    const auto  kp2 = make_keypair(24);
    const Bytes enc = crypto::elgamal::ElGamal(kp.public_key).encrypt(Bytes {0x42});
    const Bytes dec = crypto::elgamal::ElGamal(kp2.private_key).decrypt(enc);
    ASSERT_NE(dec, Bytes {0x42});
}

TEST_F(ElGamalTest, ZeroMessageRoundtrip) {
    crypto::elgamal::ElGamal elg(kp);
    const Bytes              dec = elg.decrypt(elg.encrypt(Bytes {0x00}));
    ASSERT_EQ(dec, Bytes {0x00});
}

TEST_F(ElGamalTest, PlaintextTooLargeThrows) {
    crypto::elgamal::ElGamal elg(kp);
    Bytes                    big(16, 0xFF);
    ASSERT_THROW(elg.encrypt(big), std::invalid_argument);
}

TEST_F(ElGamalTest, CorruptedCiphertextLengthThrows) {
    crypto::elgamal::ElGamal elg(kp.private_key);
    ASSERT_THROW(elg.decrypt(Bytes {0x01}), std::invalid_argument);
}

TEST_F(ElGamalTest, LargerKeySizeRoundtrip) {
    auto                     kp64 = make_keypair(32);
    crypto::elgamal::ElGamal elg(kp64);
    const Bytes              msg = {0x11, 0x22, 0x33, 0x44};
    const Bytes              dec = elg.decrypt(elg.encrypt(msg));
    ASSERT_EQ(dec, msg);
}
