
#pragma once

#include <array>
#include <cstdint>

namespace crypto::aes {

constexpr uint16_t RIJNDAEL_MODULUS = 0x11B;
constexpr uint8_t  RIJNDAEL_AFFINE_C = 0x63;

std::array<uint8_t, 256> build_sbox(uint16_t modulus = RIJNDAEL_MODULUS);

std::array<uint8_t, 256> build_inv_sbox(uint16_t modulus = RIJNDAEL_MODULUS);

} // namespace crypto::aes
