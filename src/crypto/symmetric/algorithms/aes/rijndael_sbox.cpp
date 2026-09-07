#include "rijndael_sbox.hpp"

#include "math/gf2n/gf2n_polynomial.hpp"
#include <cstdint>

namespace crypto::aes {

namespace {

uint8_t rotl8(uint8_t x, unsigned n) {
    return static_cast<uint8_t>((x << n) | (x >> (8 - n)));
}

uint8_t gf_inverse(uint8_t value, uint16_t modulus) {
    return static_cast<uint8_t>(math::gf2n::Gf2nPolynomial::inverse(
                                    math::gf2n::Gf2nPolynomial(value),
                                    math::gf2n::Gf2nPolynomial(modulus))
                                    .bits());
}

uint8_t affine_forward(uint8_t value, uint8_t c) {
    uint8_t y = 0;
    for (unsigned i = 0; i < 8; ++i) {
        auto bit = static_cast<uint8_t>(
            ((value >> i) & 1U) ^ ((value >> ((i + 4) % 8)) & 1U) ^
            ((value >> ((i + 5) % 8)) & 1U) ^ ((value >> ((i + 6) % 8)) & 1U) ^
            ((value >> ((i + 7) % 8)) & 1U) ^ ((c >> i) & 1U));
        y |= static_cast<uint8_t>(bit << i);
    }
    return y;
}

uint8_t affine_inverse(uint8_t value, uint8_t c) {
    value ^= c;
    return static_cast<uint8_t>(rotl8(value, 1) ^ rotl8(value, 3) ^ rotl8(value, 6));
}

} // namespace

std::array<uint8_t, 256> build_sbox(uint16_t modulus) {
    std::array<uint8_t, 256> sbox {};
    for (unsigned v = 0; v < 256; ++v) {
        uint8_t inverse = gf_inverse(static_cast<uint8_t>(v), modulus);
        sbox[v] = affine_forward(inverse, RIJNDAEL_AFFINE_C);
    }
    return sbox;
}

std::array<uint8_t, 256> build_inv_sbox(uint16_t modulus) {
    std::array<uint8_t, 256> inv_sbox {};
    for (unsigned s = 0; s < 256; ++s) {
        uint8_t pre = affine_inverse(static_cast<uint8_t>(s), RIJNDAEL_AFFINE_C);
        inv_sbox[s] = gf_inverse(pre, modulus);
    }
    return inv_sbox;
}

} // namespace crypto::aes
