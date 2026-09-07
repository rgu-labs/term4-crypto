#include "internal/bits/substitute.hpp"
#include <cstdint>
#include <gtest/gtest.h>

using namespace crypto::bits;

TEST(substitute_tests, simple_mapping) {
    std::array<uint8_t, 256> s_block {};
    s_block[0b010] = 0b11;
    s_block[0b101] = 0b01;
    std::vector<uint8_t> input = {0b01010101};
    auto                 out = substitute(input, s_block, 3, 2);
    EXPECT_EQ(out[0], 0b11010100);
}

TEST(substitute_tests, reverse_mapping) {
    std::array<uint8_t, 256> s_block {};
    s_block[0b0001] = 0b101;
    s_block[0b1110] = 0b111;
    std::vector<uint8_t> input = {0b11100001};
    auto                 out = substitute(input, s_block, 4, 3);
    EXPECT_EQ(out[0], 0b11110100);
}

TEST(substitute_tests, identity_mapping) {
    std::array<uint8_t, 256> s_block {};
    for (int i = 0; i < 8; i++) {
        s_block[i] = i & 0b111;
    }
    std::vector<uint8_t> input = {0b01010101};
    auto                 out = substitute(input, s_block, 3, 3);
    EXPECT_EQ(out[0], 0b01010101);
}

TEST(substitute_tests, custom_mapping) {
    std::array<uint8_t, 256> s_block {};
    s_block[0b0011] = 0b100;
    s_block[0b1100] = 0b011;
    std::vector<uint8_t> input = {0b00111100};
    auto                 out = substitute(input, s_block, 4, 3);
    EXPECT_EQ(out[0], 0b10001100);
}

TEST(substitute_tests, zero_one_flip) {
    std::array<uint8_t, 256> s_block {};
    s_block[0b0] = 0b1;
    s_block[0b1] = 0b0;
    std::vector<uint8_t> input = {0b11010010};
    auto                 out = substitute(input, s_block, 1, 1);
    EXPECT_EQ(out[0], 0b00101101);
}

TEST(substitute_tests, partial_fill) {
    std::array<uint8_t, 256> s_block {};
    s_block[0b010] = 0b11;
    s_block[0b101] = 0b01;
    std::vector<uint8_t> input = {0b01010101};
    auto                 out = substitute(input, s_block, 3, 2);
    EXPECT_EQ(out[0], 0b11010100);
}

TEST(substitute_tests, edge_cases) {
    std::array<uint8_t, 256> s_block {};
    s_block[0b0000] = 0b11;
    s_block[0b1111] = 0b00;
    std::vector<uint8_t> input = {0b11110000};
    auto                 out = substitute(input, s_block, 4, 2);
    EXPECT_EQ(out[0], 0b00110000);
}

TEST(substitute_tests, random_mapping) {
    std::array<uint8_t, 256> s_block {};
    s_block[0b0110] = 0b10;
    s_block[0b1001] = 0b01;
    std::vector<uint8_t> input = {0b01101001};
    auto                 out = substitute(input, s_block, 4, 2);
    EXPECT_EQ(out[0], 0b10010000);
}

TEST(substitute_tests, two_bytes_to_four_bytes) {
    std::array<uint8_t, 256> s_block {};
    s_block[0b00] = 0b1010;
    s_block[0b01] = 0b1100;
    s_block[0b10] = 0b0001;
    s_block[0b11] = 0b1101;
    std::vector<uint8_t> input = {0b11111111, 0b00111001};
    auto                 out = substitute(input, s_block, 2, 4);
    EXPECT_EQ(out[0], 0b11011101);
    EXPECT_EQ(out[1], 0b11011101);
    EXPECT_EQ(out[2], 0b10101101);
    EXPECT_EQ(out[3], 0b00011100);
}

TEST(substitute_wrappers, unordered_map_wrapper) {
    std::unordered_map<uint8_t, uint8_t> s_map {{0b010, 0b11}, {0b101, 0b01}};
    std::vector<uint8_t>                 input = {0b01010101};
    auto                                 out = substitute(input, s_map, 3, 2);
    EXPECT_EQ(out[0], 0b11010100);
}

TEST(substitute_wrappers, function_wrapper) {
    auto s_func = [](uint8_t x) -> uint8_t {
        if (x == 0b010) {
            return 0b11;
        }
        if (x == 0b101) {
            return 0b01;
        }
        return 0;
    };
    std::vector<uint8_t> input = {0b01010101};
    auto                 out = substitute(input, s_func, 3, 2);
    EXPECT_EQ(out[0], 0b11010100);
}
