#include <gtest/gtest.h>

#include <memory>

#include "crypto/asymmetric/algorithms/rabin/rabin.hpp"
#include "math/miller_rabin_prime_test.hpp"

using namespace crypto;

static crypto::rabin::RabinKeyPair make_keypair(mp_bitcnt_t bits = 40) {
    return crypto::rabin::KeyGenerator(
               std::make_unique<math::MillerRabinPrimeTest>(), bits, 0.9999)
        .generate();
}

static bool are_primes_3_mod_4(const crypto::rabin::RabinKeyPair &kp) {
    return (kp.private_key.p % 4) == 3 && (kp.private_key.q % 4) == 3;
}

class RabinTest : public ::testing::Test {
  protected:
    void SetUp() override {
        kp = make_keypair(40);
    }
    crypto::rabin::RabinKeyPair kp;
};

TEST_F(RabinTest, KeyPrimesAreThreeModFour) {
    ASSERT_TRUE(are_primes_3_mod_4(kp));
}

TEST_F(RabinTest, EncryptDecryptSingleByte) {
    crypto::rabin::Rabin r(kp);
    const Bytes          msg = {0x42};
    const Bytes          enc = r.encrypt(msg);
    const Bytes          dec = r.decrypt(enc);
    ASSERT_EQ(dec, msg);
}

TEST_F(RabinTest, EncryptDecryptMultipleBytes) {
    auto                 kp40 = make_keypair(40);
    crypto::rabin::Rabin r(kp40);
    const Bytes          msg = {0x01, 0x02, 0x03, 0x04};
    const Bytes          enc = r.encrypt(msg);
    const Bytes          dec = r.decrypt(enc);
    ASSERT_EQ(dec, msg);
}

TEST_F(RabinTest, EncryptDecryptLongArbitraryLength) {
    auto                 kp48 = make_keypair(48);
    crypto::rabin::Rabin r(kp48);
    Bytes                msg;
    for (unsigned i = 0; i < 257; ++i) {
        msg.push_back(static_cast<uint8_t>((i * 7 + 3) & 0xFF));
    }
    const Bytes dec = r.decrypt(r.encrypt(msg));
    ASSERT_EQ(dec, msg);
}

TEST_F(RabinTest, EncryptedDiffersFromPlaintext) {
    crypto::rabin::Rabin r(kp);
    const Bytes          msg = {0x07};
    const Bytes          enc = r.encrypt(msg);
    ASSERT_NE(enc, msg);
}

TEST_F(RabinTest, ZeroByteRoundtrip) {
    crypto::rabin::Rabin r(kp);
    const Bytes          dec = r.decrypt(r.encrypt(Bytes {0x00}));
    ASSERT_EQ(dec, Bytes {0x00});
}

TEST_F(RabinTest, EmptyMessageRoundtrip) {
    auto                 kp48 = make_keypair(48);
    crypto::rabin::Rabin r(kp48);
    const Bytes          msg;
    const Bytes          dec = r.decrypt(r.encrypt(msg));
    ASSERT_EQ(dec, msg);
}

TEST_F(RabinTest, MessageWithLeadingZerosRoundtrip) {
    auto                 kp48 = make_keypair(48);
    crypto::rabin::Rabin r(kp48);
    const Bytes          msg = {0x00, 0x00, 0x01, 0x00, 0xAB, 0x00};
    const Bytes          dec = r.decrypt(r.encrypt(msg));
    ASSERT_EQ(dec, msg);
}

TEST_F(RabinTest, PubOnlyCanEncrypt) {
    crypto::rabin::Rabin r(kp.public_key);
    ASSERT_NO_THROW(r.encrypt(Bytes {0x2A}));
}

TEST_F(RabinTest, PubOnlyCannotDecrypt) {
    crypto::rabin::Rabin r(kp.public_key);
    const Bytes          enc = crypto::rabin::Rabin(kp).encrypt(Bytes {0x2A});
    ASSERT_THROW(r.decrypt(enc), std::logic_error);
}

TEST_F(RabinTest, PrivOnlyCanDecrypt) {
    const Bytes          enc = crypto::rabin::Rabin(kp).encrypt(Bytes {0x2A});
    crypto::rabin::Rabin r(kp.private_key);
    ASSERT_NO_THROW(r.decrypt(enc));
}

TEST_F(RabinTest, PrivOnlyCannotEncrypt) {
    crypto::rabin::Rabin r(kp.private_key);
    ASSERT_THROW(r.encrypt(Bytes {0x2A}), std::logic_error);
}

TEST_F(RabinTest, EncryptWithPubDecryptWithPriv) {
    auto        kp48 = make_keypair(48);
    const Bytes msg = {0xDE, 0xAD, 0xBE, 0xEF};
    const Bytes enc = crypto::rabin::Rabin(kp48.public_key).encrypt(msg);
    const Bytes dec = crypto::rabin::Rabin(kp48.private_key).decrypt(enc);
    ASSERT_EQ(dec, msg);
}

TEST_F(RabinTest, WrongPrivateKeyFailsDecrypt) {
    const auto  kp2 = make_keypair(40);
    const Bytes enc = crypto::rabin::Rabin(kp.public_key).encrypt(Bytes {0x42});
    try {
        const Bytes dec = crypto::rabin::Rabin(kp2.private_key).decrypt(enc);
        ASSERT_NE(dec, Bytes {0x42});
    } catch (const std::runtime_error &) {
        SUCCEED();
    }
}

TEST_F(RabinTest, CorruptedCiphertextLengthThrows) {
    crypto::rabin::Rabin r(kp.private_key);
    ASSERT_THROW(r.decrypt(Bytes {0x01}), std::invalid_argument);
}

TEST_F(RabinTest, CorruptedCiphertextContentThrows) {
    crypto::rabin::Rabin r(kp);
    const Bytes          enc = r.encrypt(Bytes {0xAB, 0xCD});
    Bytes                corrupted = enc;
    corrupted[corrupted.size() - 1] ^= 0x01;
    ASSERT_THROW(r.decrypt(corrupted), std::runtime_error);
}

TEST_F(RabinTest, EmptyCiphertextThrows) {
    crypto::rabin::Rabin r(kp.private_key);
    ASSERT_THROW(r.decrypt(Bytes {}), std::invalid_argument);
}
