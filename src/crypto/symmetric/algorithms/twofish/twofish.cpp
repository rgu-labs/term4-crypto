#include "twofish.hpp"
#include <stdexcept>

namespace crypto::twofish {
const uint8_t Twofish::Q0[256] = {
    0xA9, 0x67, 0xB3, 0xE8, 0x04, 0xFD, 0xA3, 0x76,
    0x9A, 0x92, 0x80, 0x78, 0xE4, 0xDD, 0xD1, 0x38,
    0x0D, 0xC6, 0x35, 0x98, 0x18, 0xF7, 0xEC, 0x6C,
    0x43, 0x75, 0x37, 0x26, 0xFA, 0x13, 0x94, 0x48,
    0xF2, 0xD0, 0x8B, 0x30, 0x84, 0x54, 0xDF, 0x23,
    0x19, 0x5B, 0x3D, 0x59, 0xF3, 0xAE, 0xA2, 0x82,
    0x63, 0x01, 0x83, 0x2E, 0xD9, 0x51, 0x9B, 0x7C,
    0xA6, 0xEB, 0xA5, 0xBE, 0x16, 0x0C, 0xE3, 0x61,
    0xC0, 0x8C, 0x3A, 0xF5, 0x73, 0x2C, 0x25, 0x0B,
    0xBB, 0x4E, 0x89, 0x6B, 0x53, 0x6A, 0xB4, 0xF1,
    0xE1, 0xE6, 0xBD, 0x45, 0xE2, 0xF4, 0xB6, 0x66,
    0xCC, 0x95, 0x03, 0x56, 0xD4, 0x1C, 0x1E, 0xD7,
    0xFB, 0xC3, 0x8E, 0xB5, 0xE9, 0xCF, 0xBF, 0xBA,
    0xEA, 0x77, 0x39, 0xAF, 0x33, 0xC9, 0x62, 0x71,
    0x81, 0x79, 0x09, 0xAD, 0x24, 0xCD, 0xF9, 0xD8,
    0xE5, 0xC5, 0xB9, 0x4D, 0x44, 0x08, 0x86, 0xE7,
    0xA1, 0x1D, 0xAA, 0xED, 0x06, 0x70, 0xB2, 0xD2,
    0x41, 0x7B, 0xA0, 0x11, 0x31, 0xC2, 0x27, 0x90,
    0x20, 0xF6, 0x60, 0xFF, 0x96, 0x5C, 0xB1, 0xAB,
    0x9E, 0x9C, 0x52, 0x1B, 0x5F, 0x93, 0x0A, 0xEF,
    0x91, 0x85, 0x49, 0xEE, 0x2D, 0x4F, 0x8F, 0x3B,
    0x47, 0x87, 0x6D, 0x46, 0xD6, 0x3E, 0x69, 0x64,
    0x2A, 0xCE, 0xCB, 0x2F, 0xFC, 0x97, 0x05, 0x7A,
    0xAC, 0x7F, 0xD5, 0x1A, 0x4B, 0x0E, 0xA7, 0x5A,
    0x28, 0x14, 0x3F, 0x29, 0x88, 0x3C, 0x4C, 0x02,
    0xB8, 0xDA, 0xB0, 0x17, 0x55, 0x1F, 0x8A, 0x7D,
    0x57, 0xC7, 0x8D, 0x74, 0xB7, 0xC4, 0x9F, 0x72,
    0x7E, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34,
    0x6E, 0x50, 0xDE, 0x68, 0x65, 0xBC, 0xDB, 0xF8,
    0xC8, 0xA8, 0x2B, 0x40, 0xDC, 0xFE, 0x32, 0xA4,
    0xCA, 0x10, 0x21, 0xF0, 0xD3, 0x5D, 0x0F, 0x00,
    0x6F, 0x9D, 0x36, 0x42, 0x4A, 0x5E, 0xC1, 0xE0};

const uint8_t Twofish::Q1[256] = {
    0x75, 0xF3, 0xC6, 0xF4, 0xDB, 0x7B, 0xFB, 0xC8,
    0x4A, 0xD3, 0xE6, 0x6B, 0x45, 0x7D, 0xE8, 0x4B,
    0xD6, 0x32, 0xD8, 0xFD, 0x37, 0x71, 0xF1, 0xE1,
    0x30, 0x0F, 0xF8, 0x1B, 0x87, 0xFA, 0x06, 0x3F,
    0x5E, 0xBA, 0xAE, 0x5B, 0x8A, 0x00, 0xBC, 0x9D,
    0x6D, 0xC1, 0xB1, 0x0E, 0x80, 0x5D, 0xD2, 0xD5,
    0xA0, 0x84, 0x07, 0x14, 0xB5, 0x90, 0x2C, 0xA3,
    0xB2, 0x73, 0x4C, 0x54, 0x92, 0x74, 0x36, 0x51,
    0x38, 0xB0, 0xBD, 0x5A, 0xFC, 0x60, 0x62, 0x96,
    0x6C, 0x42, 0xF7, 0x10, 0x7C, 0x28, 0x27, 0x8C,
    0x13, 0x95, 0x9C, 0xC7, 0x24, 0x46, 0x3B, 0x70,
    0xCA, 0xE3, 0x85, 0xCB, 0x11, 0xD0, 0x93, 0xB8,
    0xA6, 0x83, 0x20, 0xFF, 0x9F, 0x77, 0xC3, 0xCC,
    0x03, 0x6F, 0x08, 0xBF, 0x40, 0xE7, 0x2B, 0xE2,
    0x79, 0x0C, 0xAA, 0x82, 0x41, 0x3A, 0xEA, 0xB9,
    0xE4, 0x9A, 0xA4, 0x97, 0x7E, 0xDA, 0x7A, 0x17,
    0x66, 0x94, 0xA1, 0x1D, 0x3D, 0xF0, 0xDE, 0xB3,
    0x0B, 0x72, 0xA7, 0x1C, 0xEF, 0xD1, 0x53, 0x3E,
    0x8F, 0x33, 0x26, 0x5F, 0xEC, 0x76, 0x2A, 0x49,
    0x81, 0x88, 0xEE, 0x21, 0xC4, 0x1A, 0xEB, 0xD9,
    0xC5, 0x39, 0x99, 0xCD, 0xAD, 0x31, 0x8B, 0x01,
    0x18, 0x23, 0xDD, 0x1F, 0x4E, 0x2D, 0xF9, 0x48,
    0x4F, 0xF2, 0x65, 0x8E, 0x78, 0x5C, 0x58, 0x19,
    0x8D, 0xE5, 0x98, 0x57, 0x67, 0x7F, 0x05, 0x64,
    0xAF, 0x63, 0xB6, 0xFE, 0xF5, 0xB7, 0x3C, 0xA5,
    0xCE, 0xE9, 0x68, 0x44, 0xE0, 0x4D, 0x43, 0x69,
    0x29, 0x2E, 0xAC, 0x15, 0x59, 0xA8, 0x0A, 0x9E,
    0x6E, 0x47, 0xDF, 0x34, 0x35, 0x6A, 0xCF, 0xDC,
    0x22, 0xC9, 0xC0, 0x9B, 0x89, 0xD4, 0xED, 0xAB,
    0x12, 0xA2, 0x0D, 0x52, 0xBB, 0x02, 0x2F, 0xA9,
    0xD7, 0x61, 0x1E, 0xB4, 0x50, 0x04, 0xF6, 0xC2,
    0x16, 0x25, 0x86, 0x56, 0x55, 0x09, 0xBE, 0x91};

const uint8_t Twofish::MDS[4][4] = {
    {0x01, 0xEF, 0x5B, 0x5B},
    {0x5B, 0xEF, 0xEF, 0x01},
    {0xEF, 0x5B, 0x01, 0xEF},
    {0xEF, 0x01, 0xEF, 0x5B}};

const uint8_t Twofish::RS[4][8] = {
    {0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E},
    {0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5},
    {0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19},
    {0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03}};

uint8_t Twofish::gf_mult(uint8_t a, uint8_t b, uint8_t poly) {
    uint8_t result = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) {
            result ^= a;
        }
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi) {
            a ^= poly;
        }
        b >>= 1;
    }
    return result;
}

uint32_t Twofish::mds_mult(uint8_t y0, uint8_t y1, uint8_t y2, uint8_t y3) {
    uint8_t in[4] = {y0, y1, y2, y3};
    uint8_t out[4] = {0, 0, 0, 0};
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            out[i] ^= gf_mult(MDS[i][j], in[j], 0x69);
        }
    }
    return static_cast<uint32_t>(out[0]) | (static_cast<uint32_t>(out[1]) << 8) | (static_cast<uint32_t>(out[2]) << 16) | (static_cast<uint32_t>(out[3]) << 24);
}

uint32_t Twofish::rs_mult(const uint8_t *key8, int group) {
    uint8_t out[4] = {0, 0, 0, 0};
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 8; j++) {
            out[i] ^= gf_mult(RS[i][j], key8[group * 8 + j], 0x4D);
        }
    }
    return static_cast<uint32_t>(out[0]) | (static_cast<uint32_t>(out[1]) << 8) | (static_cast<uint32_t>(out[2]) << 16) | (static_cast<uint32_t>(out[3]) << 24);
}

uint8_t Twofish::q_byte(const uint8_t *q, uint8_t x) {
    return q[x];
}

uint32_t Twofish::rol32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

uint32_t Twofish::ror32(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

void Twofish::key_schedule(const Bytes &key) {
    size_t key_len = key.size();
    if (key_len != 16 && key_len != 24 && key_len != 32) {
        throw std::invalid_argument("Twofish: key must be 16, 24 or 32 bytes");
    }

    m_k = static_cast<int>(key_len / 8);

    Bytes padded_key(32, 0);
    for (int i = 0; i < static_cast<int>(key_len); i++) {
        padded_key[i] = key[i];
    }

    std::array<uint32_t, 4> Me {}, Mo {}, S {};

    for (int i = 0; i < m_k; i++) {
        uint32_t word = 0;
        for (int j = 0; j < 4; j++) {
            word |= (static_cast<uint32_t>(padded_key[8 * i + j * 2])) << (j * 8);
        }
        Me[i] = word;

        word = 0;
        for (int j = 0; j < 4; j++) {
            word |= (static_cast<uint32_t>(padded_key[8 * i + j * 2 + 1])) << (j * 8);
        }
        Mo[i] = word;

        S[m_k - 1 - i] = rs_mult(padded_key.data(), i);
    }

    std::array<uint32_t, 4> S_arr {};
    for (int i = 0; i < m_k; i++) {
        S_arr[i] = S[i];
    }

    uint32_t rho = 0x01010101u;
    for (int i = 0; i < 20; i++) {
        uint32_t A = h_func(static_cast<uint32_t>(2 * i) * rho, Me, m_k);
        uint32_t B = rol32(h_func(static_cast<uint32_t>(2 * i + 1) * rho, Mo, m_k), 8);
        m_subkeys[2 * i] = (A + B) & 0xFFFFFFFFu;
        m_subkeys[2 * i + 1] = rol32((A + 2 * B) & 0xFFFFFFFFu, 9);
    }

    for (int i = 0; i < 256; i++) {
        auto    x = static_cast<uint8_t>(i);
        uint8_t b0, b1, b2, b3;

        if (m_k == 4) {
            b0 = Q1[x] ^ static_cast<uint8_t>(S_arr[3]);
            b1 = Q0[x] ^ static_cast<uint8_t>(S_arr[3] >> 8);
            b2 = Q0[x] ^ static_cast<uint8_t>(S_arr[3] >> 16);
            b3 = Q1[x] ^ static_cast<uint8_t>(S_arr[3] >> 24);
            b0 = Q1[b0] ^ static_cast<uint8_t>(S_arr[2]);
            b1 = Q1[b1] ^ static_cast<uint8_t>(S_arr[2] >> 8);
            b2 = Q0[b2] ^ static_cast<uint8_t>(S_arr[2] >> 16);
            b3 = Q0[b3] ^ static_cast<uint8_t>(S_arr[2] >> 24);
            b0 = Q0[Q1[b0] ^ static_cast<uint8_t>(S_arr[1])] ^ static_cast<uint8_t>(S_arr[0]);
            b1 = Q0[Q0[b1] ^ static_cast<uint8_t>(S_arr[1] >> 8)] ^ static_cast<uint8_t>(S_arr[0] >> 8);
            b2 = Q1[Q1[b2] ^ static_cast<uint8_t>(S_arr[1] >> 16)] ^ static_cast<uint8_t>(S_arr[0] >> 16);
            b3 = Q1[Q0[b3] ^ static_cast<uint8_t>(S_arr[1] >> 24)] ^ static_cast<uint8_t>(S_arr[0] >> 24);
        } else if (m_k == 3) {
            b0 = Q1[x] ^ static_cast<uint8_t>(S_arr[2]);
            b1 = Q0[x] ^ static_cast<uint8_t>(S_arr[2] >> 8);
            b2 = Q0[x] ^ static_cast<uint8_t>(S_arr[2] >> 16);
            b3 = Q1[x] ^ static_cast<uint8_t>(S_arr[2] >> 24);
            b0 = Q0[Q1[b0] ^ static_cast<uint8_t>(S_arr[1])] ^ static_cast<uint8_t>(S_arr[0]);
            b1 = Q0[Q0[b1] ^ static_cast<uint8_t>(S_arr[1] >> 8)] ^ static_cast<uint8_t>(S_arr[0] >> 8);
            b2 = Q1[Q1[b2] ^ static_cast<uint8_t>(S_arr[1] >> 16)] ^ static_cast<uint8_t>(S_arr[0] >> 16);
            b3 = Q1[Q0[b3] ^ static_cast<uint8_t>(S_arr[1] >> 24)] ^ static_cast<uint8_t>(S_arr[0] >> 24);
        } else {
            b0 = Q0[Q1[x] ^ static_cast<uint8_t>(S_arr[1])] ^ static_cast<uint8_t>(S_arr[0]);
            b1 = Q0[Q0[x] ^ static_cast<uint8_t>(S_arr[1] >> 8)] ^ static_cast<uint8_t>(S_arr[0] >> 8);
            b2 = Q1[Q1[x] ^ static_cast<uint8_t>(S_arr[1] >> 16)] ^ static_cast<uint8_t>(S_arr[0] >> 16);
            b3 = Q1[Q0[x] ^ static_cast<uint8_t>(S_arr[1] >> 24)] ^ static_cast<uint8_t>(S_arr[0] >> 24);
        }

        uint32_t val = mds_mult(b0, b1, b2, b3);
        m_sbox[0][i] = static_cast<uint8_t>(val);
        m_sbox[1][i] = static_cast<uint8_t>(val >> 8);
        m_sbox[2][i] = static_cast<uint8_t>(val >> 16);
        m_sbox[3][i] = static_cast<uint8_t>(val >> 24);
    }
}

uint32_t Twofish::h_func(uint32_t x, const std::array<uint32_t, 4> &L, int k) {
    auto b0 = static_cast<uint8_t>(x);
    auto b1 = static_cast<uint8_t>(x >> 8);
    auto b2 = static_cast<uint8_t>(x >> 16);
    auto b3 = static_cast<uint8_t>(x >> 24);

    if (k == 4) {
        b0 = Q1[b0] ^ static_cast<uint8_t>(L[3]);
        b1 = Q0[b1] ^ static_cast<uint8_t>(L[3] >> 8);
        b2 = Q0[b2] ^ static_cast<uint8_t>(L[3] >> 16);
        b3 = Q1[b3] ^ static_cast<uint8_t>(L[3] >> 24);
        b0 = Q1[b0] ^ static_cast<uint8_t>(L[2]);
        b1 = Q1[b1] ^ static_cast<uint8_t>(L[2] >> 8);
        b2 = Q0[b2] ^ static_cast<uint8_t>(L[2] >> 16);
        b3 = Q0[b3] ^ static_cast<uint8_t>(L[2] >> 24);
        b0 = Q0[Q1[b0] ^ static_cast<uint8_t>(L[1])] ^ static_cast<uint8_t>(L[0]);
        b1 = Q0[Q0[b1] ^ static_cast<uint8_t>(L[1] >> 8)] ^ static_cast<uint8_t>(L[0] >> 8);
        b2 = Q1[Q1[b2] ^ static_cast<uint8_t>(L[1] >> 16)] ^ static_cast<uint8_t>(L[0] >> 16);
        b3 = Q1[Q0[b3] ^ static_cast<uint8_t>(L[1] >> 24)] ^ static_cast<uint8_t>(L[0] >> 24);
    } else if (k == 3) {
        b0 = Q1[b0] ^ static_cast<uint8_t>(L[2]);
        b1 = Q0[b1] ^ static_cast<uint8_t>(L[2] >> 8);
        b2 = Q0[b2] ^ static_cast<uint8_t>(L[2] >> 16);
        b3 = Q1[b3] ^ static_cast<uint8_t>(L[2] >> 24);
        b0 = Q0[Q1[b0] ^ static_cast<uint8_t>(L[1])] ^ static_cast<uint8_t>(L[0]);
        b1 = Q0[Q0[b1] ^ static_cast<uint8_t>(L[1] >> 8)] ^ static_cast<uint8_t>(L[0] >> 8);
        b2 = Q1[Q1[b2] ^ static_cast<uint8_t>(L[1] >> 16)] ^ static_cast<uint8_t>(L[0] >> 16);
        b3 = Q1[Q0[b3] ^ static_cast<uint8_t>(L[1] >> 24)] ^ static_cast<uint8_t>(L[0] >> 24);
    } else {
        b0 = Q0[Q1[b0] ^ static_cast<uint8_t>(L[1])] ^ static_cast<uint8_t>(L[0]);
        b1 = Q0[Q0[b1] ^ static_cast<uint8_t>(L[1] >> 8)] ^ static_cast<uint8_t>(L[0] >> 8);
        b2 = Q1[Q1[b2] ^ static_cast<uint8_t>(L[1] >> 16)] ^ static_cast<uint8_t>(L[0] >> 16);
        b3 = Q1[Q0[b3] ^ static_cast<uint8_t>(L[1] >> 24)] ^ static_cast<uint8_t>(L[0] >> 24);
    }

    return mds_mult(b0, b1, b2, b3);
}

uint32_t Twofish::g_func(uint32_t x) const {
    auto b0 = static_cast<uint8_t>(x);
    auto b1 = static_cast<uint8_t>(x >> 8);
    auto b2 = static_cast<uint8_t>(x >> 16);
    auto b3 = static_cast<uint8_t>(x >> 24);

    return static_cast<uint32_t>(m_sbox[0][b0]) | (static_cast<uint32_t>(m_sbox[1][b1]) << 8) | (static_cast<uint32_t>(m_sbox[2][b2]) << 16) | (static_cast<uint32_t>(m_sbox[3][b3]) << 24);
}

void Twofish::set_encryption_key(const Bytes &key) {
    key_schedule(key);
}

void Twofish::set_decryption_key(const Bytes &key) {
    key_schedule(key);
}

Bytes Twofish::encrypt_block(const Bytes &block) const {
    if (block.size() != BLOCK_SIZE) {
        throw std::invalid_argument("Twofish: block must be 16 bytes");
    }

    uint32_t A = static_cast<uint32_t>(block[0]) | (static_cast<uint32_t>(block[1]) << 8) | (static_cast<uint32_t>(block[2]) << 16) | (static_cast<uint32_t>(block[3]) << 24);
    uint32_t B = static_cast<uint32_t>(block[4]) | (static_cast<uint32_t>(block[5]) << 8) | (static_cast<uint32_t>(block[6]) << 16) | (static_cast<uint32_t>(block[7]) << 24);
    uint32_t C = static_cast<uint32_t>(block[8]) | (static_cast<uint32_t>(block[9]) << 8) | (static_cast<uint32_t>(block[10]) << 16) | (static_cast<uint32_t>(block[11]) << 24);
    uint32_t D = static_cast<uint32_t>(block[12]) | (static_cast<uint32_t>(block[13]) << 8) | (static_cast<uint32_t>(block[14]) << 16) | (static_cast<uint32_t>(block[15]) << 24);

    A ^= m_subkeys[0];
    B ^= m_subkeys[1];
    C ^= m_subkeys[2];
    D ^= m_subkeys[3];

    for (int r = 0; r < ROUNDS; r++) {
        uint32_t T0 = g_func(A);
        uint32_t T1 = g_func(rol32(B, 8));
        uint32_t F0 = (T0 + T1 + m_subkeys[2 * r + 8]) & 0xFFFFFFFFu;
        uint32_t F1 = (T0 + 2 * T1 + m_subkeys[2 * r + 9]) & 0xFFFFFFFFu;

        C = ror32(C ^ F0, 1);
        D = rol32(D, 1) ^ F1;

        uint32_t tmp = A;
        A = C;
        C = tmp;
        tmp = B;
        B = D;
        D = tmp;
    }

    A ^= m_subkeys[4];
    B ^= m_subkeys[5];
    C ^= m_subkeys[6];
    D ^= m_subkeys[7];

    Bytes result(16);
    result[0] = static_cast<uint8_t>(A);
    result[1] = static_cast<uint8_t>(A >> 8);
    result[2] = static_cast<uint8_t>(A >> 16);
    result[3] = static_cast<uint8_t>(A >> 24);
    result[4] = static_cast<uint8_t>(B);
    result[5] = static_cast<uint8_t>(B >> 8);
    result[6] = static_cast<uint8_t>(B >> 16);
    result[7] = static_cast<uint8_t>(B >> 24);
    result[8] = static_cast<uint8_t>(C);
    result[9] = static_cast<uint8_t>(C >> 8);
    result[10] = static_cast<uint8_t>(C >> 16);
    result[11] = static_cast<uint8_t>(C >> 24);
    result[12] = static_cast<uint8_t>(D);
    result[13] = static_cast<uint8_t>(D >> 8);
    result[14] = static_cast<uint8_t>(D >> 16);
    result[15] = static_cast<uint8_t>(D >> 24);
    return result;
}

Bytes Twofish::decrypt_block(const Bytes &block) const {
    if (block.size() != BLOCK_SIZE) {
        throw std::invalid_argument("Twofish: block must be 16 bytes");
    }

    uint32_t A = static_cast<uint32_t>(block[0]) | (static_cast<uint32_t>(block[1]) << 8) | (static_cast<uint32_t>(block[2]) << 16) | (static_cast<uint32_t>(block[3]) << 24);
    uint32_t B = static_cast<uint32_t>(block[4]) | (static_cast<uint32_t>(block[5]) << 8) | (static_cast<uint32_t>(block[6]) << 16) | (static_cast<uint32_t>(block[7]) << 24);
    uint32_t C = static_cast<uint32_t>(block[8]) | (static_cast<uint32_t>(block[9]) << 8) | (static_cast<uint32_t>(block[10]) << 16) | (static_cast<uint32_t>(block[11]) << 24);
    uint32_t D = static_cast<uint32_t>(block[12]) | (static_cast<uint32_t>(block[13]) << 8) | (static_cast<uint32_t>(block[14]) << 16) | (static_cast<uint32_t>(block[15]) << 24);

    A ^= m_subkeys[4];
    B ^= m_subkeys[5];
    C ^= m_subkeys[6];
    D ^= m_subkeys[7];

    for (int r = ROUNDS - 1; r >= 0; r--) {
        uint32_t tmp = A;
        A = C;
        C = tmp;
        tmp = B;
        B = D;
        D = tmp;

        uint32_t T0 = g_func(A);
        uint32_t T1 = g_func(rol32(B, 8));
        uint32_t F0 = (T0 + T1 + m_subkeys[2 * r + 8]) & 0xFFFFFFFFu;
        uint32_t F1 = (T0 + 2 * T1 + m_subkeys[2 * r + 9]) & 0xFFFFFFFFu;

        C = rol32(C, 1) ^ F0;
        D = ror32(D ^ F1, 1);
    }

    A ^= m_subkeys[0];
    B ^= m_subkeys[1];
    C ^= m_subkeys[2];
    D ^= m_subkeys[3];

    Bytes result(16);
    result[0] = static_cast<uint8_t>(A);
    result[1] = static_cast<uint8_t>(A >> 8);
    result[2] = static_cast<uint8_t>(A >> 16);
    result[3] = static_cast<uint8_t>(A >> 24);
    result[4] = static_cast<uint8_t>(B);
    result[5] = static_cast<uint8_t>(B >> 8);
    result[6] = static_cast<uint8_t>(B >> 16);
    result[7] = static_cast<uint8_t>(B >> 24);
    result[8] = static_cast<uint8_t>(C);
    result[9] = static_cast<uint8_t>(C >> 8);
    result[10] = static_cast<uint8_t>(C >> 16);
    result[11] = static_cast<uint8_t>(C >> 24);
    result[12] = static_cast<uint8_t>(D);
    result[13] = static_cast<uint8_t>(D >> 8);
    result[14] = static_cast<uint8_t>(D >> 16);
    result[15] = static_cast<uint8_t>(D >> 24);
    return result;
}

size_t Twofish::block_size() const {
    return BLOCK_SIZE;
}
} // namespace crypto::twofish
