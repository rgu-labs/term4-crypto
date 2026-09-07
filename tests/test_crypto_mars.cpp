#include "crypto/symmetric/algorithms/mars/mars.hpp"
#include "gtest/gtest.h"
#include <cstdint>
#include <iomanip>
#include <vector>

using namespace crypto::mars;

static std::string vec_to_hex(const std::vector<uint8_t> &v) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (auto byte : v) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

TEST(MARS_tests, zero_key_zero_block) {
    MARS                 mars;
    std::vector<uint8_t> key(16, 0x00);
    std::vector<uint8_t> block(16, 0x00);

    mars.set_encryption_key(key);
    mars.set_decryption_key(key);

    auto enc = mars.encrypt_block(block);
    auto dec = mars.decrypt_block(enc);

    EXPECT_EQ(block, dec);
}

TEST(MARS_tests, max_value_key_block) {
    MARS                 mars;
    std::vector<uint8_t> key(16, 0xFF);
    std::vector<uint8_t> block(16, 0xFF);

    mars.set_encryption_key(key);
    mars.set_decryption_key(key);

    auto enc = mars.encrypt_block(block);
    auto dec = mars.decrypt_block(enc);

    EXPECT_EQ(block, dec);
}

TEST(MARS_tests, encrypt_decrypt_roundtrip_128) {
    MARS                 mars;
    std::vector<uint8_t> key = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
    std::vector<uint8_t> block = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    mars.set_encryption_key(key);
    mars.set_decryption_key(key);

    auto enc = mars.encrypt_block(block);
    auto dec = mars.decrypt_block(enc);

    EXPECT_NE(enc, block);
    EXPECT_EQ(dec, block);
}

TEST(MARS_tests, encrypt_decrypt_roundtrip_256) {
    MARS                 mars;
    std::vector<uint8_t> key = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    std::vector<uint8_t> block(16, 0xA5);

    mars.set_encryption_key(key);
    mars.set_decryption_key(key);

    auto enc = mars.encrypt_block(block);
    auto dec = mars.decrypt_block(enc);

    EXPECT_NE(enc, block);
    EXPECT_EQ(dec, block);
}

TEST(MARS_tests, deterministic) {
    MARS                 mars;
    std::vector<uint8_t> key(16, 0x42);
    std::vector<uint8_t> block(16, 0x37);

    mars.set_encryption_key(key);

    auto enc1 = mars.encrypt_block(block);
    auto enc2 = mars.encrypt_block(block);

    EXPECT_EQ(enc1, enc2);
}

TEST(MARS_tests, different_keys_different_ciphertext) {
    MARS                 m1;
    MARS                 m2;
    std::vector<uint8_t> key1(16, 0x00);
    std::vector<uint8_t> key2(16, 0xFF);
    std::vector<uint8_t> block(16, 0x00);

    m1.set_encryption_key(key1);
    m2.set_encryption_key(key2);

    auto enc1 = m1.encrypt_block(block);
    auto enc2 = m2.encrypt_block(block);

    EXPECT_NE(enc1, enc2);
}

TEST(MARS_tests, block_size) {
    MARS mars;
    EXPECT_EQ(mars.block_size(), 16u);
}

TEST(MARS_tests, invalid_key_size) {
    MARS                 mars;
    std::vector<uint8_t> bad_key(10, 0x00);
    EXPECT_THROW(mars.set_encryption_key(bad_key), std::invalid_argument);
}

TEST(MARS_tests, invalid_block_size) {
    MARS                 mars;
    std::vector<uint8_t> key(16, 0x00);
    mars.set_encryption_key(key);
    std::vector<uint8_t> bad_block(8, 0x00);
    EXPECT_THROW(mars.encrypt_block(bad_block), std::invalid_argument);
}

TEST(MARS_tests, random_blocks_128) {
    MARS                 mars;
    std::vector<uint8_t> key(16);
    for (int i = 0; i < 16; i++) {
        key[i] = static_cast<uint8_t>(i * 17 + 3);
    }

    mars.set_encryption_key(key);
    mars.set_decryption_key(key);

    for (int t = 0; t < 20; t++) {
        std::vector<uint8_t> block(16);
        for (int i = 0; i < 16; i++) {
            block[i] = static_cast<uint8_t>(rand() % 256);
        }

        auto enc = mars.encrypt_block(block);
        auto dec = mars.decrypt_block(enc);

        EXPECT_EQ(block, dec) << "Failed at t=" << t
                              << " block=" << vec_to_hex(block)
                              << " enc=" << vec_to_hex(enc)
                              << " dec=" << vec_to_hex(dec);
    }
}

TEST(MARS_tests, random_blocks_256) {
    MARS                 mars;
    std::vector<uint8_t> key(32);
    for (int i = 0; i < 32; i++) {
        key[i] = static_cast<uint8_t>(i * 7 + 11);
    }

    mars.set_encryption_key(key);
    mars.set_decryption_key(key);

    for (int t = 0; t < 20; t++) {
        std::vector<uint8_t> block(16);
        for (int i = 0; i < 16; i++) {
            block[i] = static_cast<uint8_t>(rand() % 256);
        }

        auto enc = mars.encrypt_block(block);
        auto dec = mars.decrypt_block(enc);

        EXPECT_EQ(block, dec) << "Failed at t=" << t
                              << " block=" << vec_to_hex(block)
                              << " enc=" << vec_to_hex(enc)
                              << " dec=" << vec_to_hex(dec);
    }
}
