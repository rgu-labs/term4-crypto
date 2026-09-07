#include "utils.hpp"
#include <cstdint>
#include <cstdio>
#include <stdexcept>

namespace crypto::bits {

std::vector<uint8_t> rotate_left(const std::vector<uint8_t> &bits,
                                 size_t n_bits, size_t shift) {
    if (bits.empty() || n_bits == 0) {
        return {};
    }

    shift %= n_bits;
    if (shift == 0) {
        return bits;
    }

    std::vector<uint8_t> res;
    res.resize(bits.size(), 0);

    for (auto i = 0; i < n_bits; i++) {
        const auto new_pos = (i + n_bits - shift) % n_bits;
        const auto src_byte = i / 8;
        const auto src_bit = 7 - (i % 8);
        const auto dst_byte = new_pos / 8;
        const auto dst_bit = 7 - (new_pos % 8);

        uint8_t bit_val = (bits[src_byte] >> (src_bit) & 1);
        res[dst_byte] &= ~(1 << (dst_bit));
        res[dst_byte] |= bit_val << (dst_bit);
    }

    const auto extra_bits = res.size() * 8 - n_bits;
    if (extra_bits > 0) {
        res.back() &= 0xFF >> extra_bits;
    }

    return res;
}

std::vector<uint8_t> rotate_right(const std::vector<uint8_t> &bits,
                                  size_t n_bits, size_t shift) {
    if (bits.empty() || n_bits == 0) {
        return {};
    }

    shift %= n_bits;
    if (shift == 0) {
        return bits;
    }

    std::vector<uint8_t> res;
    res.resize(bits.size(), 0);

    for (auto i = 0; i < n_bits; i++) {
        const auto new_pos = (i + n_bits + shift) % n_bits;
        const auto src_byte = i / 8;
        const auto src_bit = 7 - (i % 8);
        const auto dst_byte = new_pos / 8;
        const auto dst_bit = 7 - (new_pos % 8);

        uint8_t bit_val = (bits[src_byte] >> (src_bit) & 1);
        res[dst_byte] &= ~(1 << (dst_bit));
        res[dst_byte] |= bit_val << (dst_bit);
    }

    const auto extra_bits = res.size() * 8 - n_bits;
    if (extra_bits > 0) {
        res.back() &= 0xFF >> extra_bits;
    }

    return res;
}

std::vector<uint8_t> apply_mask(const std::vector<uint8_t> &bits,
                                const std::vector<uint8_t> &mask,
                                size_t mask_bits, MaskType mask_type) {
    auto const n_bits = bits.size() * 8;

    if (mask_bits > n_bits) {
        throw std::invalid_argument("Mask longer than bits array");
    }

    std::vector<uint8_t> result(bits);

    for (auto i = 0; i < n_bits; i++) {
        auto const byte_index = i / 8;
        auto const bit_index = 7 - (i % 8);

        uint8_t  mask_bit = (mask[byte_index] >> bit_index) & 1;
        uint8_t &bit_ref = result[byte_index];
        uint8_t  bit_mask = 1 << bit_index;

        switch (mask_type) {
            case MaskType::And:
                if (mask_bit == 0) {
                    bit_ref &= ~bit_mask;
                }
                break;
            case MaskType::Or:
                if (mask_bit == 1) {
                    bit_ref |= bit_mask;
                }
                break;
            case MaskType::Xor:
                if (mask_bit == 1) {
                    bit_ref ^= bit_mask;
                }
                break;
        }
    }
    return result;
}

std::vector<uint8_t> get_bits(const std::vector<uint8_t> &bits, size_t i,
                              size_t j) {
    if (i > j) {
        return {};
    }

    const size_t total_bits = bits.size() * 8;
    if (j >= total_bits) {
        throw std::invalid_argument("index out of bounds");
    }

    const auto           bit_len = j - i + 1;
    const auto           out_bytes = (bit_len + 7) / 8;
    std::vector<uint8_t> out(out_bytes, 0);

    for (size_t k = i; k <= j; k++) {
        uint8_t    bit_val = get_bit(bits, k);
        size_t     out_index = k - i;
        const auto dst_byte = out_index / 8;
        const auto dst_bit = 7 - (out_index % 8);
        out[dst_byte] |= bit_val << dst_bit;
    }

    return out;
}

void swap_bits(std::vector<uint8_t> &bits, size_t i, size_t j) {
    if (i == j || bits.empty()) {
        return;
    }

    uint8_t bit_i = get_bit(bits, i);
    uint8_t bit_j = get_bit(bits, j);

    set_bit(bits, i, bit_j);
    set_bit(bits, j, bit_i);
}

uint8_t get_bit(const std::vector<uint8_t> &bits, size_t index) {
    if (index >= bits.size() * 8) {
        throw std::invalid_argument("index out of bounds");
    }

    const auto byte = index / 8;
    const auto bit = 7 - (index % 8);
    return (bits[byte] >> bit) & 1;
}

void set_bit(std::vector<uint8_t> &bits, size_t index, uint8_t val) {
    if (index >= bits.size() * 8) {
        throw std::invalid_argument("index out of bounds");
    }

    const auto byte = index / 8;
    const auto bit = 7 - (index % 8);
    bits[byte] &= ~(1 << bit);
    bits[byte] |= (val & 1) << bit;
}

} // namespace crypto::bits
