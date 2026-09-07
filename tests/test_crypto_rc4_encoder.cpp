#include "stream/algorithms/rc4/encoder.hpp"
#include <cstdint>
#include <gtest/gtest.h>
#include <vector>

using namespace crypto::rc4;

TEST(rc4_test, encrypt_decrypt_simple) {
    std::vector<uint8_t> key = {1, 2, 3};
    std::vector<uint8_t> data = {10, 20, 30, 40};

    std::vector<uint8_t> original = data;

    Encoder rc4(key);
    rc4.encode(data);

    EXPECT_NE(data, original);

    rc4.mutate(key);
    rc4.encode(data);

    EXPECT_EQ(data, original);
}

TEST(rc4_test, empty_buffer) {
    std::vector<uint8_t> key = {1, 2, 3};
    std::vector<uint8_t> data;

    std::vector<uint8_t> original = data;

    Encoder rc4_enc(key);
    rc4_enc.encode(data);

    EXPECT_EQ(data, original);
}

TEST(rc4_test, different_keys) {
    std::vector<uint8_t> key1 = {1, 2, 3};
    std::vector<uint8_t> key2 = {4, 5, 6};

    std::vector<uint8_t> data = {10, 20, 30, 40};

    std::vector<uint8_t> buf1 = data;
    std::vector<uint8_t> buf2 = data;

    Encoder rc4(key1);
    rc4.encode(buf1);

    rc4.mutate(key2);
    rc4.encode(buf2);

    EXPECT_NE(buf1, buf2);
}
