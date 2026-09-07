#include <gtest/gtest.h>
#include <cstdlib>
#include <filesystem>

#include "math/miller_rabin_prime_test.hpp"
#include "asymmetric/algorithms/rsa/key_generator.hpp"
#include "asymmetric/algorithms/rsa/key_serializer.hpp"

static crypto::rsa::KeyPair make_keypair(mp_bitcnt_t bits = 512) {
    return crypto::rsa::KeyGenerator(
               std::make_unique<math::MillerRabinPrimeTest>(),
               bits,
               0.9999)
        .generate();
}

static int openssl(const std::string &args) {
    return std::system(("openssl " + args + " > /dev/null 2>&1").c_str());
}

class RsaKeySerializerTest : public ::testing::Test {
  protected:
    void SetUp() override {
        kp = make_keypair(512);
        pub_path = "/tmp/test_rsa_pub.pem";
        priv_path = "/tmp/test_rsa_priv.pem";
        crypto::rsa::KeySerializer::save_public_key(kp.public_key, pub_path);
        crypto::rsa::KeySerializer::save_private_key(kp.private_key, priv_path);
    }

    void TearDown() override {
        std::filesystem::remove(pub_path);
        std::filesystem::remove(priv_path);
    }

    crypto::rsa::KeyPair kp;
    std::string          pub_path;
    std::string          priv_path;
};

TEST_F(RsaKeySerializerTest, PublicKeyFileExists) {
    ASSERT_TRUE(std::filesystem::exists(pub_path));
}

TEST_F(RsaKeySerializerTest, PrivateKeyFileExists) {
    ASSERT_TRUE(std::filesystem::exists(priv_path));
}

TEST_F(RsaKeySerializerTest, PublicKeyFileNotEmpty) {
    ASSERT_GT(std::filesystem::file_size(pub_path), 0u);
}

TEST_F(RsaKeySerializerTest, PrivateKeyFileNotEmpty) {
    ASSERT_GT(std::filesystem::file_size(priv_path), 0u);
}

TEST_F(RsaKeySerializerTest, OpensslParsesPublicKey) {
    ASSERT_EQ(openssl("rsa -RSAPublicKey_in -in " + pub_path + " -text -noout"), 0);
}

TEST_F(RsaKeySerializerTest, OpensslParsesPrivateKey) {
    ASSERT_EQ(openssl("rsa -in " + priv_path + " -text -noout"), 0);
}

TEST_F(RsaKeySerializerTest, OpensslChecksPrivateKey) {
    ASSERT_EQ(openssl("rsa -in " + priv_path + " -check"), 0);
}

TEST_F(RsaKeySerializerTest, LoadedPublicKeyModulusMatches) {
    const auto loaded = crypto::rsa::KeySerializer::load_public_key(pub_path);
    ASSERT_EQ(loaded.n, kp.public_key.n);
}

TEST_F(RsaKeySerializerTest, LoadedPublicKeyExponentMatches) {
    const auto loaded = crypto::rsa::KeySerializer::load_public_key(pub_path);
    ASSERT_EQ(loaded.e, kp.public_key.e);
}

TEST_F(RsaKeySerializerTest, LoadedPrivateKeyModulusMatches) {
    const auto loaded = crypto::rsa::KeySerializer::load_private_key(priv_path);
    ASSERT_EQ(loaded.n, kp.private_key.n);
}

TEST_F(RsaKeySerializerTest, LoadedPrivateKeyExponentMatches) {
    const auto loaded = crypto::rsa::KeySerializer::load_private_key(priv_path);
    ASSERT_EQ(loaded.e, kp.private_key.e);
}

TEST_F(RsaKeySerializerTest, LoadedPrivateKeyDMatches) {
    const auto loaded = crypto::rsa::KeySerializer::load_private_key(priv_path);
    ASSERT_EQ(loaded.d, kp.private_key.d);
}

TEST_F(RsaKeySerializerTest, LoadedPrivateKeyPMatches) {
    const auto loaded = crypto::rsa::KeySerializer::load_private_key(priv_path);
    ASSERT_EQ(loaded.p, kp.private_key.p);
}

TEST_F(RsaKeySerializerTest, LoadedPrivateKeyQMatches) {
    const auto loaded = crypto::rsa::KeySerializer::load_private_key(priv_path);
    ASSERT_EQ(loaded.q, kp.private_key.q);
}

TEST_F(RsaKeySerializerTest, LoadedPrivateKeyDpMatches) {
    const auto loaded = crypto::rsa::KeySerializer::load_private_key(priv_path);
    ASSERT_EQ(loaded.dp, kp.private_key.dp);
}

TEST_F(RsaKeySerializerTest, LoadedPrivateKeyDqMatches) {
    const auto loaded = crypto::rsa::KeySerializer::load_private_key(priv_path);
    ASSERT_EQ(loaded.dq, kp.private_key.dq);
}

TEST_F(RsaKeySerializerTest, LoadedPrivateKeyQpMatches) {
    const auto loaded = crypto::rsa::KeySerializer::load_private_key(priv_path);
    ASSERT_EQ(loaded.qp, kp.private_key.qp);
}

TEST_F(RsaKeySerializerTest, LoadNonExistentPublicKeyThrows) {
    ASSERT_THROW(
        crypto::rsa::KeySerializer::load_public_key("/tmp/nonexistent.pem"),
        std::runtime_error);
}

TEST_F(RsaKeySerializerTest, LoadNonExistentPrivateKeyThrows) {
    ASSERT_THROW(
        crypto::rsa::KeySerializer::load_private_key("/tmp/nonexistent.pem"),
        std::runtime_error);
}

TEST_F(RsaKeySerializerTest, RoundtripPublicKeyMatchesOriginal) {
    const auto loaded = crypto::rsa::KeySerializer::load_public_key(pub_path);
    ASSERT_EQ(loaded.n, kp.public_key.n);
    ASSERT_EQ(loaded.e, kp.public_key.e);
}

TEST_F(RsaKeySerializerTest, RoundtripPrivateKeyMatchesOriginal) {
    const auto loaded = crypto::rsa::KeySerializer::load_private_key(priv_path);
    ASSERT_EQ(loaded.n, kp.private_key.n);
    ASSERT_EQ(loaded.e, kp.private_key.e);
    ASSERT_EQ(loaded.d, kp.private_key.d);
    ASSERT_EQ(loaded.p, kp.private_key.p);
    ASSERT_EQ(loaded.q, kp.private_key.q);
    ASSERT_EQ(loaded.dp, kp.private_key.dp);
    ASSERT_EQ(loaded.dq, kp.private_key.dq);
    ASSERT_EQ(loaded.qp, kp.private_key.qp);
}
