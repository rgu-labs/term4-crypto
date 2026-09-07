#include <gtest/gtest.h>

#include "asymmetric/algorithms/dh/dh.hpp"
#include "asymmetric/algorithms/dh/dh_params.hpp"

static crypto::dh::DhParams small_params() {
    return {mpz_class(23), mpz_class(5)};
}

static crypto::dh::DhParams large_params() {
    mpz_class p("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
                "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
                "83655D23DCA3AD961C62F356208552BB9ED529077096966D6"
                "70C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE3"
                "9E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE"
                "2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
                16);
    mpz_class g(2);
    return {p, g};
}

TEST(DiffieHellmanTest, SharedSecretMatches_SmallParams) {
    const auto                params = small_params();
    crypto::dh::DiffieHellman alice(params);
    crypto::dh::DiffieHellman bob(params);

    const mpz_class sa = alice.compute_shared_secret(bob.public_key());
    const mpz_class sb = bob.compute_shared_secret(alice.public_key());
    ASSERT_EQ(sa, sb);
}

TEST(DiffieHellmanTest, SharedSecretMatches_LargeParams) {
    const auto                params = large_params();
    crypto::dh::DiffieHellman alice(params);
    crypto::dh::DiffieHellman bob(params);

    const mpz_class sa = alice.compute_shared_secret(bob.public_key());
    const mpz_class sb = bob.compute_shared_secret(alice.public_key());
    ASSERT_EQ(sa, sb);
}

TEST(DiffieHellmanTest, PublicKeyInRange) {
    const auto                params = small_params();
    crypto::dh::DiffieHellman alice(params);
    ASSERT_GE(alice.public_key(), mpz_class(1));
    ASSERT_LT(alice.public_key(), params.p);
}

TEST(DiffieHellmanTest, PublicKeysAreDifferent) {
    const auto                params = large_params();
    crypto::dh::DiffieHellman alice(params);
    crypto::dh::DiffieHellman bob(params);
    ASSERT_NE(alice.public_key(), bob.public_key());
}

TEST(DiffieHellmanTest, SharedSecretBytesSize_DES) {
    const auto                params = large_params();
    crypto::dh::DiffieHellman alice(params);
    crypto::dh::DiffieHellman bob(params);

    const auto key = alice.shared_secret_bytes(bob.public_key(), 8);
    ASSERT_EQ(key.size(), 8u);
}

TEST(DiffieHellmanTest, SharedSecretBytesSize_MARS) {
    const auto                params = large_params();
    crypto::dh::DiffieHellman alice(params);
    crypto::dh::DiffieHellman bob(params);

    const auto key_a = alice.shared_secret_bytes(bob.public_key(), 16);
    const auto key_b = bob.shared_secret_bytes(alice.public_key(), 16);
    ASSERT_EQ(key_a.size(), 16u);
    ASSERT_EQ(key_a, key_b);
}

TEST(DiffieHellmanTest, SharedSecretBytesMatch_DES) {
    const auto                params = large_params();
    crypto::dh::DiffieHellman alice(params);
    crypto::dh::DiffieHellman bob(params);

    const auto key_a = alice.shared_secret_bytes(bob.public_key(), 8);
    const auto key_b = bob.shared_secret_bytes(alice.public_key(), 8);
    ASSERT_EQ(key_a, key_b);
}

TEST(DiffieHellmanTest, SharedSecretBytesMatch_AES128) {
    const auto                params = large_params();
    crypto::dh::DiffieHellman alice(params);
    crypto::dh::DiffieHellman bob(params);

    const auto key_a = alice.shared_secret_bytes(bob.public_key(), 16);
    const auto key_b = bob.shared_secret_bytes(alice.public_key(), 16);
    ASSERT_EQ(key_a, key_b);
}

TEST(DiffieHellmanTest, SharedSecretBytesMatch_AES256) {
    const auto                params = large_params();
    crypto::dh::DiffieHellman alice(params);
    crypto::dh::DiffieHellman bob(params);

    const auto key_a = alice.shared_secret_bytes(bob.public_key(), 32);
    const auto key_b = bob.shared_secret_bytes(alice.public_key(), 32);
    ASSERT_EQ(key_a, key_b);
}

TEST(DiffieHellmanTest, InvalidParams_SmallP) {
    ASSERT_THROW(
        crypto::dh::DiffieHellman({mpz_class(1), mpz_class(2)}),
        std::invalid_argument);
}

TEST(DiffieHellmanTest, InvalidParams_GOutOfRange) {
    ASSERT_THROW(
        crypto::dh::DiffieHellman({mpz_class(23), mpz_class(23)}),
        std::invalid_argument);
}

TEST(DiffieHellmanTest, InvalidOtherPublicKey) {
    const auto                params = small_params();
    crypto::dh::DiffieHellman alice(params);
    ASSERT_THROW(alice.compute_shared_secret(mpz_class(0)), std::invalid_argument);
    ASSERT_THROW(alice.compute_shared_secret(mpz_class(23)), std::invalid_argument);
}

TEST(DiffieHellmanTest, MultipleSessionsDifferentSecrets) {
    const auto params = large_params();

    crypto::dh::DiffieHellman alice1(params);
    crypto::dh::DiffieHellman bob1(params);
    const auto                key1 = alice1.shared_secret_bytes(bob1.public_key(), 16);

    crypto::dh::DiffieHellman alice2(params);
    crypto::dh::DiffieHellman bob2(params);
    const auto                key2 = alice2.shared_secret_bytes(bob2.public_key(), 16);

    ASSERT_NE(key1, key2);
}
