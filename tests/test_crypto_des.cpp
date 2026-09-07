#include "crypto/symmetric/algorithms/des/des.hpp"
#include "gtest/gtest.h"
#include <cstdint>
#include <iomanip>
#include <vector>

using namespace crypto::des;

std::string vec_to_hex(const std::vector<uint8_t> &v) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (auto byte : v) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

TEST(DES_tests, zero_key_and_block) {
    DES                  des;
    std::vector<uint8_t> key(8, 0x00);
    std::vector<uint8_t> block(8, 0x00);

    des.set_encryption_key(key);
    des.set_decryption_key(key);

    auto enc = des.encrypt_block(block);
    auto dec = des.decrypt_block(enc);

    EXPECT_EQ(block, dec) << "Decryption failed for all-zero block/key";
}

TEST(DES_tests, max_value_key_and_block) {
    DES                  des;
    std::vector<uint8_t> key(8, 0xFF);
    std::vector<uint8_t> block(8, 0xFF);

    des.set_encryption_key(key);
    des.set_decryption_key(key);

    auto enc = des.encrypt_block(block);
    auto dec = des.decrypt_block(enc);

    EXPECT_EQ(block, dec) << "Decryption failed for all-0xFF block/key";
}

TEST(DES_tests, symmetric_encryption) {
    DES                  des;
    std::vector<uint8_t> key = {0x10, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    std::vector<uint8_t> block = {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};

    des.set_encryption_key(key);
    des.set_decryption_key(key);

    auto enc1 = des.encrypt_block(block);
    auto enc2 = des.encrypt_block(block);

    EXPECT_EQ(enc1, enc2) << "Encryption is not deterministic";

    auto dec = des.decrypt_block(enc1);
    EXPECT_EQ(block, dec) << "Decryption failed for non-trivial block/key";
}

TEST(DES_tests, long_data_multiple_blocks) {
    DES                  des;
    DES                  des2;
    std::vector<uint8_t> key = {0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1};
    std::vector<uint8_t> key2 = {0xA3, 0xF4, 0x3A, 0x52, 0xBB, 0x0B, 0xCF, 0xF4};
    des.set_encryption_key(key);
    des.set_decryption_key(key);

    des2.set_encryption_key(key2);
    des2.set_decryption_key(key2);

    std::vector<uint8_t> data = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                                 0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
                                 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88};

    std::vector<uint8_t> encrypted(data.size());
    std::vector<uint8_t> encrypted2(data.size());
    for (int i = 0; i < data.size(); i += 8) {
        std::vector<uint8_t> block(data.begin() + i, data.begin() + i + 8);
        auto                 enc = des.encrypt_block(block);
        auto                 enc2 = des2.encrypt_block(block);
        std::copy(enc.begin(), enc.end(), encrypted.begin() + i);
        std::copy(enc2.begin(), enc2.end(), encrypted2.begin() + i);
    }

    EXPECT_NE(encrypted, data);
    EXPECT_NE(encrypted2, data);
    EXPECT_NE(encrypted2, encrypted);

    std::vector<uint8_t> decrypted(data.size());
    std::vector<uint8_t> decrypted2(data.size());
    for (size_t i = 0; i < encrypted.size(); i += 8) {
        std::vector<uint8_t> block(encrypted.begin() + i,
                                   encrypted.begin() + i + 8);

        std::vector<uint8_t> block2(encrypted2.begin() + i,
                                    encrypted2.begin() + i + 8);
        auto                 dec = des.decrypt_block(block);
        auto                 dec2 = des2.decrypt_block(block2);
        std::copy(dec.begin(), dec.end(), decrypted.begin() + i);
        std::copy(dec2.begin(), dec2.end(), decrypted2.begin() + i);
    }

    EXPECT_EQ(data, decrypted);
    EXPECT_EQ(data, decrypted2);
}

TEST(DES_tests, random_blocks) {
    DES                  des;
    std::vector<uint8_t> key = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    des.set_encryption_key(key);
    des.set_decryption_key(key);

    for (int i = 0; i < 10; ++i) {
        std::vector<uint8_t> block(8);
        for (auto &b : block) {
            b = rand() % 256;
        }

        auto enc = des.encrypt_block(block);
        EXPECT_NE(block, enc);
        auto dec = des.decrypt_block(enc);

        EXPECT_EQ(block, dec) << "Random block failed: " << vec_to_hex(block)
                              << " enc: " << vec_to_hex(enc)
                              << " dec: " << vec_to_hex(dec);
    }
}
