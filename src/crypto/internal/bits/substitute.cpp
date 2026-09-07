#include "substitute.hpp"
#include <cstdint>
#include <iostream>
#include <stdexcept>

namespace crypto::bits {

std::vector<uint8_t> substitute(const std::vector<uint8_t>     &bits,
                                const std::array<uint8_t, 256> &s_block,
                                size_t block_size_in, size_t block_size_out) {
    if (block_size_in == 0) {
        return bits;
    }
    if (block_size_out == 0) {
        return {};
    }

    constexpr size_t max_bits = 8;
    if (block_size_in > max_bits || block_size_out > max_bits) {
        throw std::invalid_argument(
            "Block size must be <= 8 bits for uint8_t S-box");
    }

    const auto total_bits_in = bits.size() * 8;
    const auto total_blocks = total_bits_in / block_size_in;
    const auto remaining_bits = total_bits_in % block_size_in;
    const auto total_bits_out = total_blocks * block_size_out + remaining_bits;
    const auto out_size = (total_bits_out + 7) / 8;

    std::vector<uint8_t> result(out_size, 0);
    auto                 out_bit_pos = 0;

    for (auto block = 0; block < total_blocks; ++block) {
        uint8_t    key = 0;
        const auto base_bit = block * block_size_in;
        for (auto b = 0; b < block_size_in; ++b) {
            const auto byte_idx = (base_bit + b) / 8;
            const auto bit_idx = 7 - ((base_bit + b) % 8);

            key = (key << 1) | ((bits[byte_idx] >> bit_idx) & 1);
        }

        uint8_t output_bits = s_block[key] & ((1 << block_size_out) - 1);

        for (auto b = 0; b < block_size_out; ++b) {
            const auto out_byte_idx = out_bit_pos / 8;
            const auto out_bit_idx = 7 - (out_bit_pos % 8);

            const uint8_t bit_val = (output_bits >> (block_size_out - 1 - b)) & 1;
            result[out_byte_idx] |= bit_val << out_bit_idx;
            ++out_bit_pos;
        }
    }

    if (remaining_bits > 0) {
        const auto base_bit = total_blocks * block_size_in;
        for (auto b = 0; b < remaining_bits; ++b) {
            const auto in_byte_idx = (base_bit + b) / 8;
            const auto in_bit_idx = 7 - ((base_bit + b) % 8);
            const auto bit_val = (bits[in_byte_idx] >> in_bit_idx) & 1;

            const auto out_byte_idx = out_bit_pos / 8;
            const auto out_bit_idx = 7 - (out_bit_pos % 8);

            result[out_byte_idx] |= bit_val << out_bit_idx;
            ++out_bit_pos;
        }
    }

    return result;
}

std::vector<uint8_t>
substitute(const std::vector<uint8_t>                 &bits,
           const std::unordered_map<uint8_t, uint8_t> &s_block,
           size_t block_size_in, size_t block_size_out) {
    std::array<uint8_t, 256> array_s {};
    for (auto i = 0; i < 256; ++i) {
        const auto it = s_block.find(i);
        if (it != s_block.end()) {
            array_s[i] = it->second;
        } else {
            array_s[i] = 0;
        }
    }
    return substitute(bits, array_s, block_size_in, block_size_out);
}

std::vector<uint8_t> substitute(const std::vector<uint8_t>            &bits,
                                const std::function<uint8_t(uint8_t)> &s_block,
                                size_t block_size_in, size_t block_size_out) {
    std::array<uint8_t, 256> array_s {};
    for (auto i = 0; i < 256; ++i) {
        array_s[i] = s_block(i);
    }
    return substitute(bits, array_s, block_size_in, block_size_out);
}

} // namespace crypto::bits
