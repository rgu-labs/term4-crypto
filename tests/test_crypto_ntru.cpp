#include <gtest/gtest.h>

#include <memory>

#include "crypto/asymmetric/algorithms/ntru/ntru.hpp"

using namespace crypto;

static crypto::ntru::NtruKeyPair make_keypair() {
    return crypto::ntru::KeyGenerator(crypto::ntru::NtruParams {}).generate();
}

TEST(NtruTest, GenerateKeysAndRoundtrip) {
    const auto                kp = make_keypair();
    crypto::ntru::NTRUEncrypt ntru(kp);
    const Bytes               msg = {0x48, 0x69};
    const Bytes               enc = ntru.encrypt(msg);
    const Bytes               dec = ntru.decrypt(enc);
    ASSERT_EQ(dec, msg);
}

TEST(NtruTest, RoundtripMultiByte) {
    const auto                kp = make_keypair();
    crypto::ntru::NTRUEncrypt ntru(kp);
    Bytes                     msg(6);
    for (size_t i = 0; i < msg.size(); ++i) {
        msg[i] = static_cast<uint8_t>(i * 17 + 3);
    }
    const Bytes enc = ntru.encrypt(msg);
    const Bytes dec = ntru.decrypt(enc);
    ASSERT_EQ(dec, msg);
}

TEST(NtruTest, EncryptedDiffersFromPlaintext) {
    const auto                kp = make_keypair();
    crypto::ntru::NTRUEncrypt ntru(kp);
    const Bytes               enc = ntru.encrypt(Bytes {0x07});
    ASSERT_NE(enc, Bytes {0x07});
}

TEST(NtruTest, RandomizedEncryptionDifferentEachTime) {
    const auto                kp = make_keypair();
    crypto::ntru::NTRUEncrypt ntru(kp);
    const Bytes               msg = {0x2A};
    const Bytes               enc1 = ntru.encrypt(msg);
    const Bytes               enc2 = ntru.encrypt(msg);
    ASSERT_NE(enc1, enc2);
    ASSERT_EQ(ntru.decrypt(enc1), msg);
    ASSERT_EQ(ntru.decrypt(enc2), msg);
}

TEST(NtruTest, PubOnlyCanEncrypt) {
    const auto                kp = make_keypair();
    crypto::ntru::NTRUEncrypt ntru(kp.public_key);
    ASSERT_NO_THROW(ntru.encrypt(Bytes {0x11}));
}

TEST(NtruTest, PubOnlyCannotDecrypt) {
    const auto                kp = make_keypair();
    crypto::ntru::NTRUEncrypt ntru(kp.public_key);
    const Bytes               enc = crypto::ntru::NTRUEncrypt(kp).encrypt(Bytes {0x11});
    ASSERT_THROW(ntru.decrypt(enc), std::logic_error);
}

TEST(NtruTest, PrivOnlyCanDecrypt) {
    const auto                kp = make_keypair();
    const Bytes               enc = crypto::ntru::NTRUEncrypt(kp).encrypt(Bytes {0x11});
    crypto::ntru::NTRUEncrypt ntru(kp.private_key);
    ASSERT_NO_THROW(ntru.decrypt(enc));
}

TEST(NtruTest, PrivOnlyCannotEncrypt) {
    const auto                kp = make_keypair();
    crypto::ntru::NTRUEncrypt ntru(kp.private_key);
    ASSERT_THROW(ntru.encrypt(Bytes {0x11}), std::logic_error);
}

TEST(NtruTest, EncryptWithPubDecryptWithPriv) {
    const auto  kp = make_keypair();
    const Bytes msg = {0xDE, 0xAD};
    const Bytes enc = crypto::ntru::NTRUEncrypt(kp.public_key).encrypt(msg);
    const Bytes dec = crypto::ntru::NTRUEncrypt(kp.private_key).decrypt(enc);
    ASSERT_EQ(dec, msg);
}

TEST(NtruTest, WrongKeyFailsDecrypt) {
    const auto  kp1 = make_keypair();
    const auto  kp2 = make_keypair();
    const Bytes enc =
        crypto::ntru::NTRUEncrypt(kp1.public_key).encrypt(Bytes {0x42});
    const Bytes dec = crypto::ntru::NTRUEncrypt(kp2.private_key).decrypt(enc);
    ASSERT_NE(dec, Bytes {0x42});
}

TEST(NtruTest, ZeroMessageRoundtrip) {
    const auto                kp = make_keypair();
    crypto::ntru::NTRUEncrypt ntru(kp);
    const Bytes               dec = ntru.decrypt(ntru.encrypt(Bytes {0x00}));
    ASSERT_EQ(dec, Bytes {0x00});
}

TEST(NtruTest, PlaintextTooLargeThrows) {
    const auto                kp = make_keypair();
    crypto::ntru::NTRUEncrypt ntru(kp);
    Bytes                     big(64, 0xFF);
    ASSERT_THROW(ntru.encrypt(big), std::invalid_argument);
}

TEST(NtruTest, InvalidParamsThrow) {
    ASSERT_THROW(crypto::ntru::KeyGenerator(
                     crypto::ntru::NtruParams {0, 3, 439}),
                 std::invalid_argument);
    ASSERT_THROW(crypto::ntru::KeyGenerator(
                     crypto::ntru::NtruParams {53, 3, 3}),
                 std::invalid_argument);
    ASSERT_THROW(crypto::ntru::KeyGenerator(
                     crypto::ntru::NtruParams {53, 439, 3}),
                 std::invalid_argument);
}

TEST(NtruTest, PublicKeyConsistentShape) {
    const auto kp = make_keypair();
    ASSERT_EQ(kp.public_key.h.size(), 53u);
    ASSERT_EQ(kp.private_key.f.size(), 53u);
    ASSERT_EQ(kp.private_key.f_p.size(), 53u);
}
