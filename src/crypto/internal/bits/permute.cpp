#include "permute.hpp"
#include <cstdint>
#include <vector>

namespace crypto::bits {

std::vector<uint8_t> permute(const std::vector<uint8_t> &bits,
                             const std::vector<size_t> &p_block, BitOrder order,
                             BitIndexBase index_base) {
    if (p_block.empty()) {
        return {};
    }

    size_t               out_size = (p_block.size() + 7) / 8;
    std::vector<uint8_t> out(out_size, 0);

    bool   index_base_one = index_base == BitIndexBase::One;
    bool   big_endian = order == BitOrder::BigEndian;
    size_t total_bits = bits.size() * 8;

    for (size_t i = 0; i < p_block.size(); i++) {
        size_t index = p_block[i];

        if (index_base_one) {
            index--;
        }

        if (!big_endian) {
            index = total_bits - 1 - index;
        }

        uint8_t val = 0;
        if (index < total_bits) {
            val = (bits[index / 8] >> (7 - (index % 8))) & 1;
        }

        out[i / 8] |= val << (7 - (i % 8));
    }

    return out;
}

} // namespace crypto::bits
