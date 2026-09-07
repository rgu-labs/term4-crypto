#include <cstdint>
#include <gtest/gtest.h>

#include "crypto/internal/bits/permute.hpp"
#include "common.hpp"

using namespace crypto::bits;

TEST(bits_permute_test, identity_zero_based_big_endian_multi_byte) {
    {
        auto                bits = bits_from_string("10101100001101001110100100011101");
        auto                expected = bits_from_string("10101100001101001110100100011101");
        std::vector<size_t> indexes(32);
        for (size_t i = 0; i < 32; i++) {
            indexes[i] = i;
        }
        EXPECT_EQ(expected,
                  permute(bits, indexes, BitOrder::BigEndian, BitIndexBase::Zero));
    }
}

TEST(bits_permute_test, reverse_zero_based_little_endian_multi_byte) {
    {
        auto                bits = bits_from_string("10101100001101001110100100011101");
        auto                expected = bits_from_string("10111000100101110010110000110101");
        std::vector<size_t> indexes(32);
        for (size_t i = 0; i < 32; i++) {
            indexes[i] = i;
        }
        EXPECT_EQ(expected, permute(bits, indexes, BitOrder::LittleEndian,
                                    BitIndexBase::Zero));
    }
}

TEST(bits_permute_test, identity_one_based_big_endian_multi_byte) {
    {
        auto                bits = bits_from_string("10101100001101001110100100011101");
        auto                expected = bits_from_string("10101100001101001110100100011101");
        std::vector<size_t> indexes(32);
        for (size_t i = 0; i < 32; i++) {
            indexes[i] = i + 1;
        }
        EXPECT_EQ(expected,
                  permute(bits, indexes, BitOrder::BigEndian, BitIndexBase::One));
    }
}

TEST(bits_permute_test, reverse_one_based_little_endian_multi_byte) {
    {
        auto                bits = bits_from_string("10110101101010100011100011100101");
        auto                expected = bits_from_string("10100111000111000101010110101101");
        std::vector<size_t> indexes(32);
        for (size_t i = 0; i < 32; i++) {
            indexes[i] = i + 1;
        }
        EXPECT_EQ(expected, permute(bits, indexes, BitOrder::LittleEndian,
                                    BitIndexBase::One));
    }
}

TEST(bits_permute_test, empty_vector) {
    {
        std::vector<uint8_t> bits;
        auto                 expected = std::vector<uint8_t> {};
        EXPECT_EQ(expected,
                  permute(bits, {}, BitOrder::LittleEndian, BitIndexBase::Zero));
    }
}

TEST(bits_permute_test, single_bit_vector_multi_byte) {
    {
        auto                bits = bits_from_string("10011010");
        auto                expected = bits_from_string("10011010");
        std::vector<size_t> indexes(8);
        for (size_t i = 0; i < 8; i++) {
            indexes[i] = i + 1;
        }
        EXPECT_EQ(expected,
                  permute(bits, indexes, BitOrder::BigEndian, BitIndexBase::One));
    }
}

TEST(bits_permute_test, repeated_indexes_multi_byte) {
    {
        auto                bits = bits_from_string("1010011011010011");
        auto                expected = bits_from_string("1111001111001100");
        std::vector<size_t> indexes = {2, 2, 1, 1, 6, 6, 5, 5,
                                       10, 10, 9, 9, 14, 14, 13, 13};

        auto ans =
            permute(bits, indexes, BitOrder::LittleEndian, BitIndexBase::One);
        std::cout << bits_to_string(ans) << std::endl;
        EXPECT_EQ(expected, permute(bits, indexes, BitOrder::LittleEndian,
                                    BitIndexBase::One));
    }
}

TEST(bits_permute_test, partial_permutation_multi_byte) {
    {
        auto                bits = bits_from_string("1010110001101001");
        auto                expected = bits_from_string("11101010");
        std::vector<size_t> indexes = {2, 0, 4, 6, 10, 8, 12, 14};
        EXPECT_EQ(expected,
                  permute(bits, indexes, BitOrder::BigEndian, BitIndexBase::Zero));
    }
}

TEST(bits_permute_test, out_of_range_zero_based_multi_byte) {
    {
        auto                bits = bits_from_string("1010110001101001");
        auto                expected = bits_from_string("10010011");
        std::vector<size_t> indexes = {0, 1, 3, 4, 7, 8, 10, 15};
        EXPECT_EQ(expected,
                  permute(bits, indexes, BitOrder::BigEndian, BitIndexBase::Zero));
    }
}

TEST(bits_permute_test, out_of_range_one_based_multi_byte) {
    {
        auto                bits = bits_from_string("1010110001101001");
        auto                expected = bits_from_string("10100000");
        std::vector<size_t> indexes = {1, 4, 5, 9, 12, 17, 20, 25};
        EXPECT_EQ(expected,
                  permute(bits, indexes, BitOrder::BigEndian, BitIndexBase::One));
    }
}
