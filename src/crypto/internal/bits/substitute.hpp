#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <unordered_map>
#include <vector>

namespace crypto::bits {

std::vector<uint8_t> substitute(const std::vector<uint8_t>     &bits,
                                const std::array<uint8_t, 256> &s_block,
                                size_t block_size_in, size_t block_size_out);

std::vector<uint8_t>
substitute(const std::vector<uint8_t>                 &bits,
           const std::unordered_map<uint8_t, uint8_t> &s_block,
           size_t block_size_in, size_t block_size_out);

std::vector<uint8_t> substitute(const std::vector<uint8_t>            &bits,
                                const std::function<uint8_t(uint8_t)> &s_block,
                                size_t block_size_in, size_t block_size_out);

} // namespace crypto::bits
