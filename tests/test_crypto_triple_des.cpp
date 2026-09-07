#include "crypto/symmetric/algorithms/triple_des//triple_des.hpp"
#include "gtest/gtest.h"
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <vector>

using namespace crypto::des;
using namespace crypto;

std::string vec_to_hex(const std::vector<uint8_t> &v) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (auto byte : v) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

void test_triple_des_mode(TripleDESMode mode, const Bytes &key,
                          const Bytes &block) {
    TripleDES tdes(mode);
    tdes.set_encryption_key(key);
    tdes.set_decryption_key(key);

    auto enc = tdes.encrypt_block(block);
    auto dec = tdes.decrypt_block(enc);

    EXPECT_EQ(block, dec) << "TripleDES failed for mode "
                          << static_cast<int>(mode) << " with block "
                          << vec_to_hex(block);
}

TEST(TripleDES_tests, zero_key_and_block) {
    Bytes block(8, 0x00);

    test_triple_des_mode(TripleDESMode::EEE3, Bytes(24, 0x00), block);
    test_triple_des_mode(TripleDESMode::EDE3, Bytes(24, 0x00), block);
    test_triple_des_mode(TripleDESMode::EEE2, Bytes(16, 0x00), block);
    test_triple_des_mode(TripleDESMode::EDE2, Bytes(16, 0x00), block);
}

TEST(TripleDES_tests, max_value_key_and_block) {
    Bytes block(8, 0xFF);

    test_triple_des_mode(TripleDESMode::EEE3, Bytes(24, 0xFF), block);
    test_triple_des_mode(TripleDESMode::EDE3, Bytes(24, 0xFF), block);
    test_triple_des_mode(TripleDESMode::EEE2, Bytes(16, 0xFF), block);
    test_triple_des_mode(TripleDESMode::EDE2, Bytes(16, 0xFF), block);
}

TEST(TripleDES_tests, symmetric_encryption) {
    Bytes key3 = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                  0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
                  0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78};
    Bytes block = {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};

    TripleDES tdes(TripleDESMode::EDE3);
    tdes.set_encryption_key(key3);
    tdes.set_decryption_key(key3);

    auto enc1 = tdes.encrypt_block(block);
    auto enc2 = tdes.encrypt_block(block);

    EXPECT_EQ(enc1, enc2) << "TripleDES encryption not deterministic";

    auto dec = tdes.decrypt_block(enc1);
    EXPECT_EQ(block, dec)
        << "TripleDES decryption failed for non-trivial block/key";
}

TEST(TripleDES_tests, multiple_blocks) {
    Bytes     key = {0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1,
                     0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                     0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
    TripleDES tdes(TripleDESMode::EEE3);
    tdes.set_encryption_key(key);
    tdes.set_decryption_key(key);

    Bytes data = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                  0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
                  0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88};

    Bytes encrypted(data.size());
    for (size_t i = 0; i < data.size(); i += 8) {
        Bytes block(data.begin() + i, data.begin() + i + 8);
        auto  enc = tdes.encrypt_block(block);
        std::copy(enc.begin(), enc.end(), encrypted.begin() + i);
    }

    EXPECT_NE(encrypted, data);

    Bytes decrypted(data.size());
    for (size_t i = 0; i < encrypted.size(); i += 8) {
        Bytes block(encrypted.begin() + i, encrypted.begin() + i + 8);
        auto  dec = tdes.decrypt_block(block);
        std::copy(dec.begin(), dec.end(), decrypted.begin() + i);
    }

    EXPECT_EQ(decrypted, data);
}

TEST(TripleDES_tests, random_blocks) {
    Bytes key = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
                 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78};

    TripleDES tdes(TripleDESMode::EDE3);
    tdes.set_encryption_key(key);
    tdes.set_decryption_key(key);

    for (int i = 0; i < 10; ++i) {
        Bytes block(8);
        for (auto &b : block) {
            b = rand() % 256;
        }

        auto enc = tdes.encrypt_block(block);
        EXPECT_NE(block, enc);
        auto dec = tdes.decrypt_block(enc);
        EXPECT_EQ(block, dec) << "Random TripleDES block failed: "
                              << vec_to_hex(block);
    }
}
