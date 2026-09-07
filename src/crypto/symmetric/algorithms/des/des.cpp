#include "des.hpp"
#include "internal/bits/permute.hpp"
#include "internal/bits/substitute.hpp"
#include "internal/bits/utils.hpp"
#include "../../../crypto.hpp"
#include "internal/core/feistel_network.hpp"

namespace des_tables {
static const std::vector<size_t> IP = {
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7};

static const std::vector<size_t> FP = {
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25};

static const std::vector<size_t> E = {
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11,
    12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21,
    22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1};

static const std::vector<size_t> P = {16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23,
                                      26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27,
                                      3, 9, 19, 13, 30, 6, 22, 11, 4, 25};

static constexpr std::array<uint8_t, 256> S1 = {
    14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
    0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
    4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
    15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13};

static constexpr std::array<uint8_t, 256> S2 = {
    15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
    3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
    0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
    13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9};

static constexpr std::array<uint8_t, 256> S3 = {
    10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
    13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
    13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
    1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12};

static constexpr std::array<uint8_t, 256> S4 = {
    7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
    13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
    10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
    3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14};

static constexpr std::array<uint8_t, 256> S5 = {
    2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
    14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
    4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
    11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3};

static constexpr std::array<uint8_t, 256> S6 = {
    12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
    10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
    9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
    4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13};

static constexpr std::array<uint8_t, 256> S7 = {
    4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
    13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
    1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
    6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12};

static constexpr std::array<uint8_t, 256> S8 = {
    13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
    1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
    7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
    2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11};

static constexpr std::array<std::array<uint8_t, 256>, 8> SBOXES = {
    S1, S2, S3, S4, S5, S6, S7, S8};

static const std::vector<size_t> PC1 = {
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43,
    35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54,
    46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4};

static const std::vector<size_t> PC2 = {
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32};

static const std::vector<size_t> SPLIT_C = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28};

static const std::vector<size_t> SPLIT_D = {
    29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
    43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56};

static const std::vector<size_t> COMPACT_CD = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
    20, 21, 22, 23, 24, 25, 26, 27, 28, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
    43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60};

static const std::vector<size_t> COMPACT_64_32 = {
    1, 2, 3, 4, 9, 10, 11, 12, 17, 18, 19, 20, 25, 26, 27, 28,
    33, 34, 35, 36, 41, 42, 43, 44, 49, 50, 51, 52, 57, 58, 59, 60};

static const std::vector<size_t> DES_KEY_SHIFTS = {1, 1, 2, 2, 2, 2, 2, 2,
                                                   1, 2, 2, 2, 2, 2, 2, 1};

} // namespace des_tables

namespace crypto::des {

DES::DES() : m_network(m_key_expansion, m_round_function, 16, 8),
             core::FeistelNetworkWrapper(m_network) {}

void DES::before_rounds(Bytes &block, bool encrypting) const {
    block =
        crypto::bits::permute(block, des_tables::IP, bits::BitOrder::BigEndian,
                              bits::BitIndexBase::One);

    (void)encrypting;
}

void DES::after_rounds(Bytes &block, bool encrypting) const {
    block =
        crypto::bits::permute(block, des_tables::FP, bits::BitOrder::BigEndian,
                              bits::BitIndexBase::One);

    (void)encrypting;
}

core::RoundKeys DES::KeyExpansionDES::expand(const Bytes &key) const {
    core::RoundKeys round_keys(16);

    auto cd = bits::permute(key, des_tables::PC1, bits::BitOrder::BigEndian,
                            bits::BitIndexBase::One);
    auto C = bits::permute(cd, des_tables::SPLIT_C, bits::BitOrder::BigEndian,
                           bits::BitIndexBase::One);
    auto D = bits::permute(cd, des_tables::SPLIT_D, bits::BitOrder::BigEndian,
                           bits::BitIndexBase::One);

    for (int round = 0; round < 16; round++) {

        bits::rotate_left(C, 28, des_tables::DES_KEY_SHIFTS[round]);
        bits::rotate_left(D, 28, des_tables::DES_KEY_SHIFTS[round]);

        Bytes CD;
        CD.insert(CD.end(), C.begin(), C.end());
        CD.insert(CD.end(), D.begin(), D.end());

        CD = bits::permute(CD, des_tables::COMPACT_CD, bits::BitOrder::BigEndian,
                           bits::BitIndexBase::One);

        auto round_key =
            bits::permute(CD, des_tables::PC2, bits::BitOrder::BigEndian,
                          bits::BitIndexBase::One);
        round_keys[round] = std::move(round_key);
    }

    return round_keys;
}

Bytes DES::FeistelRoundFunctionDES::apply(const Bytes &half_block,
                                          const Bytes &round_key) const {
    auto expanded_half =
        bits::permute(half_block, des_tables::E, bits::BitOrder::BigEndian,
                      bits::BitIndexBase::One);

    for (int i = 0; i < expanded_half.size(); i++) {
        expanded_half[i] ^= round_key[i];
    }

    size_t block_index = 0;

    Bytes substituted_sparce(8, 0);

    for (int i = 0; i < 8; i++) {
        size_t bit_offset = i * 6;

        std::vector<size_t>  indices = {bit_offset, bit_offset + 1,
                                        bit_offset + 2, bit_offset + 3,
                                        bit_offset + 4, bit_offset + 5};
        std::vector<uint8_t> six_bits =
            bits::permute(expanded_half, indices, bits::BitOrder::BigEndian,
                          bits::BitIndexBase::Zero);

        std::vector<uint8_t> four_bits =
            bits::substitute(six_bits, des_tables::SBOXES[i], 6, 4);

        substituted_sparce[i] = four_bits[0];
    }

    Bytes substituted =
        bits::permute(substituted_sparce, des_tables::COMPACT_64_32,
                      bits::BitOrder::BigEndian, bits::BitIndexBase::One);

    auto final_block =
        bits::permute(substituted, des_tables::P, bits::BitOrder::BigEndian,
                      bits::BitIndexBase::One);

    return final_block;
}

size_t DES::block_size() const { return m_network.block_size(); }

} // namespace crypto::des
