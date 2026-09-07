#include <gtest/gtest.h>

#include "math/miller_rabin_prime_test.hpp"
#include "asymmetric/algorithms/rsa/key_generator.hpp"
#include "asymmetric/algorithms/rsa/rsa.hpp"

using namespace crypto;

static crypto::rsa::KeyPair make_keypair(mp_bitcnt_t bits = 512) {
    return crypto::rsa::KeyGenerator(
               std::make_unique<math::MillerRabinPrimeTest>(),
               bits,
               0.9999)
        .generate();
}

static Bytes make_message(size_t size, uint8_t fill = 0x42) {
    return Bytes(size, fill);
}

class RsaTest : public ::testing::Test {
  protected:
    void SetUp() override {
        kp = make_keypair(512);
    }
    crypto::rsa::KeyPair kp;
};

TEST_F(RsaTest, EncryptDecryptSingleByte) {
    crypto::rsa::Rsa rsa(kp);
    const Bytes      msg = {0x41};
    const Bytes      enc = rsa.encrypt(msg);
    const Bytes      dec_raw = rsa.decrypt(enc);
    const Bytes      dec(dec_raw.end() - msg.size(), dec_raw.end());
    ASSERT_EQ(dec, msg);
}

TEST_F(RsaTest, EncryptDecryptMultipleBytes) {
    crypto::rsa::Rsa rsa(kp);
    const Bytes      msg = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    const Bytes      enc = rsa.encrypt(msg);
    const Bytes      dec_raw = rsa.decrypt(enc);
    const Bytes      dec(dec_raw.end() - msg.size(), dec_raw.end());
    ASSERT_EQ(dec, msg);
}

TEST_F(RsaTest, EncryptDecryptSessionKey) {
    crypto::rsa::Rsa rsa(kp);
    const Bytes      session_key = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE};
    const Bytes enc = rsa.encrypt(session_key);
    const Bytes dec_raw = rsa.decrypt(enc);
    const Bytes dec(dec_raw.end() - session_key.size(), dec_raw.end());
    ASSERT_EQ(dec, session_key);
}

TEST_F(RsaTest, EncryptedDiffersFromPlaintext) {
    crypto::rsa::Rsa rsa(kp);
    const Bytes      msg = {0x01, 0x02, 0x03, 0x04};
    const Bytes      enc = rsa.encrypt(msg);
    ASSERT_NE(enc, msg);
}

TEST_F(RsaTest, EncryptedSizeEqualsModulusSize) {
    crypto::rsa::Rsa rsa(kp);
    const Bytes      msg = {0x42};
    const Bytes      enc = rsa.encrypt(msg);
    const size_t     n_bytes = (mpz_sizeinbase(kp.public_key.n.get_mpz_t(), 2) + 7) / 8;
    ASSERT_EQ(enc.size(), n_bytes);
}

TEST_F(RsaTest, SameMessageEncryptedTwiceGivesSameResult) {
    crypto::rsa::Rsa rsa(kp);
    const Bytes      msg = {0x01, 0x02, 0x03};
    ASSERT_EQ(rsa.encrypt(msg), rsa.encrypt(msg));
}

TEST_F(RsaTest, PubOnlyConstructorCanEncrypt) {
    crypto::rsa::Rsa rsa(kp.public_key);
    const Bytes      msg = {0x42};
    ASSERT_NO_THROW(rsa.encrypt(msg));
}

TEST_F(RsaTest, PubOnlyConstructorCannotDecrypt) {
    crypto::rsa::Rsa rsa(kp.public_key);
    const Bytes      msg = {0x42};
    const Bytes      enc = crypto::rsa::Rsa(kp).encrypt(msg);
    ASSERT_THROW(rsa.decrypt(enc), std::logic_error);
}

TEST_F(RsaTest, PrivOnlyConstructorCanDecrypt) {
    const Bytes      msg = {0x42};
    const Bytes      enc = crypto::rsa::Rsa(kp.public_key).encrypt(msg);
    crypto::rsa::Rsa rsa(kp.private_key);
    ASSERT_NO_THROW(rsa.decrypt(enc));
}

TEST_F(RsaTest, PrivOnlyConstructorCannotEncrypt) {
    crypto::rsa::Rsa rsa(kp.private_key);
    const Bytes      msg = {0x42};
    ASSERT_THROW(rsa.encrypt(msg), std::logic_error);
}

TEST_F(RsaTest, EncryptWithPubDecryptWithPriv) {
    const Bytes msg = {0xDE, 0xAD, 0xBE, 0xEF};
    const Bytes enc = crypto::rsa::Rsa(kp.public_key).encrypt(msg);
    const Bytes dec_raw = crypto::rsa::Rsa(kp.private_key).decrypt(enc);
    const Bytes dec(dec_raw.end() - msg.size(), dec_raw.end());
    ASSERT_EQ(dec, msg);
}

TEST_F(RsaTest, WrongPrivateKeyFailsDecrypt) {
    const auto  kp2 = make_keypair(512);
    const Bytes msg = {0x42};
    const Bytes enc = crypto::rsa::Rsa(kp.public_key).encrypt(msg);
    const Bytes dec_raw = crypto::rsa::Rsa(kp2.private_key).decrypt(enc);
    const Bytes dec(dec_raw.end() - msg.size(), dec_raw.end());
    ASSERT_NE(dec, msg);
}

TEST_F(RsaTest, ZeroMessageRoundtrip) {
    crypto::rsa::Rsa rsa(kp);
    const Bytes      msg = {0x00};
    const Bytes      enc = rsa.encrypt(msg);
    const Bytes      dec_raw = rsa.decrypt(enc);
    const Bytes      dec(dec_raw.end() - msg.size(), dec_raw.end());
    ASSERT_EQ(dec, msg);
}
