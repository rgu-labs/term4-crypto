#include <cstdint>
#include <gtest/gtest.h>

#include "internal/bits/utils.hpp"

#include "common.hpp"

using namespace crypto::bits;

TEST(bits_get_set_test, basic_get_set) {
    auto bits = bits_from_string("10101010");
    EXPECT_EQ(get_bit(bits, 0), 1);
    EXPECT_EQ(get_bit(bits, 7), 0);

    std::vector<uint8_t> copy = bits;
    set_bit(copy, 0, 0);
    set_bit(copy, 7, 1);
    EXPECT_EQ(bits_to_string(copy), "00101011");
}

TEST(bits_swap_test, swap_msb_lsb) {
    auto bits = bits_from_string("10101010");
    swap_bits(bits, 0, 7);
    EXPECT_EQ(bits_to_string(bits), "00101011");
}

TEST(bits_swap_test, swap_same_bit) {
    auto bits = bits_from_string("10101010");
    swap_bits(bits, 3, 3);
    EXPECT_EQ(bits_to_string(bits), "10101010");
}

TEST(bits_rotate_left_test, simple_shift) {
    auto bits = bits_from_string("10110011");
    auto res = rotate_left(bits, 8, 2);
    EXPECT_EQ(bits_to_string(res), "11001110");
}

TEST(bits_rotate_left_test, zero_shift) {
    auto bits = bits_from_string("10110011");
    auto res = rotate_left(bits, 8, 0);
    EXPECT_EQ(bits_to_string(res), "10110011");
}

TEST(bits_rotate_left_test, multi_byte) {
    auto bits = bits_from_string("1011001101110001");
    auto res = rotate_left(bits, 16, 4);
    EXPECT_EQ(bits_to_string(res), "0011011100011011");
}

TEST(bits_rotate_right_test, simple_shift) {
    auto bits = bits_from_string("10110011");
    auto res = rotate_right(bits, 8, 2);
    EXPECT_EQ(bits_to_string(res), "11101100");
}

TEST(bits_rotate_right_test, zero_shift) {
    auto bits = bits_from_string("10110011");
    auto res = rotate_right(bits, 8, 0);
    EXPECT_EQ(bits_to_string(res), "10110011");
}

TEST(bits_get_bits_test, middle_slice) {
    auto bits = bits_from_string("101100111010");
    auto res = get_bits(bits, 3, 5);
    EXPECT_EQ(bits_to_string(res), "10000000");
}

TEST(bits_get_bits_test, full_range) {
    auto bits = bits_from_string("10110011");
    auto res = get_bits(bits, 0, 7);
    EXPECT_EQ(bits_to_string(res), "10110011");
}

TEST(bits_apply_mask_test, and_mask) {
    auto bits = bits_from_string("1100110100000000");
    auto mask = bits_from_string("1111000000000000");
    auto res = apply_mask(bits, mask, 16, MaskType::And);
    EXPECT_EQ(bits_to_string(res), "1100000000000000");
}

TEST(bits_apply_mask_test, or_mask) {
    auto bits = bits_from_string("1100110100000000");
    auto mask = bits_from_string("1111000000000000");
    auto res = apply_mask(bits, mask, 16, MaskType::Or);
    EXPECT_EQ(bits_to_string(res), "1111110100000000");
}

TEST(bits_apply_mask_test, xor_mask) {
    auto bits = bits_from_string("1100110100000000");
    auto mask = bits_from_string("1111000000000000");
    auto res = apply_mask(bits, mask, 16, MaskType::Xor);
    EXPECT_EQ(bits_to_string(res), "0011110100000000");
}

TEST(bits_edge_cases_test, empty_vector) {
    std::vector<uint8_t> empty;
    EXPECT_EQ(rotate_left(empty, 0, 5), std::vector<uint8_t> {});
    EXPECT_EQ(rotate_right(empty, 0, 5), std::vector<uint8_t> {});
    EXPECT_THROW(get_bits(empty, 0, 0), std::invalid_argument);
    EXPECT_EQ(apply_mask(empty, empty, 0, MaskType::And), std::vector<uint8_t> {});
}

TEST(bits_edge_cases_test, single_bit) {
    auto bits = bits_from_string("00000001");
    auto res = rotate_left(bits, 1, 1);
    EXPECT_EQ(bits_to_string(res), "00000001");
}
