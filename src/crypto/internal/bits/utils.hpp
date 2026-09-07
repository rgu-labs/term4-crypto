#pragma once

#include <cstdint>
#include <vector>

namespace crypto::bits {

enum class MaskType {
    Or,
    And,
    Xor,
};

std::vector<uint8_t> rotate_left(const std::vector<uint8_t> &bits,
                                 size_t n_bits, size_t shift);

std::vector<uint8_t> rotate_right(const std::vector<uint8_t> &bits,
                                  size_t n_bits, size_t shift);

std::vector<uint8_t> apply_mask(const std::vector<uint8_t> &bits,
                                const std::vector<uint8_t> &mask,
                                size_t mask_bits, MaskType mask_type);

std::vector<uint8_t> get_bits(const std::vector<uint8_t> &bits, size_t i,
                              size_t j);

void swap_bits(std::vector<uint8_t> &bits, size_t i, size_t j);

uint8_t get_bit(const std::vector<uint8_t> &bits, size_t index);

void set_bit(std::vector<uint8_t> &bits, size_t index, uint8_t val);

} // namespace crypto::bits
