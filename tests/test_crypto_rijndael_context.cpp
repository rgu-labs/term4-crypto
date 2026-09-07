#include <gtest/gtest.h>

#include <fstream>
#include <iterator>

#include "crypto/symmetric/cipher_context.hpp"
#include "crypto/symmetric/algorithms/aes/rijndael.hpp"

using crypto::Bytes;
using crypto::SymmetricCipherContext;
using crypto::SymmetricEncryptionMode;
using crypto::SymmetricPaddingScheme;
using crypto::aes::Rijndael;

static const char *mode_name(SymmetricEncryptionMode mode) {
    switch (mode) {
        case SymmetricEncryptionMode::ECB:
            return "ECB";
        case SymmetricEncryptionMode::CBC:
            return "CBC";
        case SymmetricEncryptionMode::PCBC:
            return "PCBC";
        case SymmetricEncryptionMode::CFB:
            return "CFB";
        case SymmetricEncryptionMode::OFB:
            return "OFB";
        case SymmetricEncryptionMode::CTR:
            return "CTR";
        case SymmetricEncryptionMode::RD:
            return "RD";
    }
    return "?";
}

static Bytes make_key(size_t bits) {
    Bytes key(bits / 8, 0x00);
    for (size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<uint8_t>(i * 0x11 + 0x03);
    }
    return key;
}

static Bytes make_iv(size_t block_bytes, SymmetricEncryptionMode mode) {
    size_t iv_size = mode == SymmetricEncryptionMode::CTR ? block_bytes - 8
                                                          : block_bytes;
    Bytes  iv(iv_size, 0x00);
    for (size_t i = 0; i < iv.size(); ++i) {
        iv[i] = static_cast<uint8_t>(i * 0x3D + 0xB7);
    }
    return iv;
}

static Bytes make_input(size_t size) {
    Bytes    input(size);
    uint32_t seed = 0x12345678;
    for (size_t i = 0; i < size; ++i) {
        seed = seed * 1664525u + 1013904223u;
        input[i] = static_cast<uint8_t>(seed >> 24);
    }
    return input;
}

static bool roundtrip(size_t block_bits, size_t key_bits,
                      SymmetricEncryptionMode mode,
                      SymmetricPaddingScheme padding, size_t threads) {
    std::unique_ptr<crypto::core::SymmetricCipher> cipher =
        std::make_unique<Rijndael>(block_bits);
    Bytes                  iv = make_iv(block_bits / 8, mode);
    SymmetricCipherContext ctx(std::move(cipher), mode, padding, iv);
    ctx.set_encryption_key(make_key(key_bits));
    ctx.set_decryption_key(make_key(key_bits));

    Bytes input = make_input(3 * block_bits / 8 + 5);
    Bytes encrypted;
    Bytes decrypted;
    ctx.encrypt(input, encrypted, threads);
    ctx.decrypt(encrypted, decrypted, threads);
    return decrypted == input;
}

TEST(RijndaelContext, AllModesAllPaddingsRoundtrip) {
    for (SymmetricEncryptionMode mode : {SymmetricEncryptionMode::ECB,
                                         SymmetricEncryptionMode::CBC,
                                         SymmetricEncryptionMode::PCBC,
                                         SymmetricEncryptionMode::CFB,
                                         SymmetricEncryptionMode::OFB,
                                         SymmetricEncryptionMode::CTR,
                                         SymmetricEncryptionMode::RD}) {
        for (SymmetricPaddingScheme padding :
             {SymmetricPaddingScheme::Zeros, SymmetricPaddingScheme::AnsiX923,
              SymmetricPaddingScheme::PKCS7, SymmetricPaddingScheme::ISO10126}) {
            EXPECT_TRUE(roundtrip(128, 128, mode, padding, 1))
                << mode_name(mode) << " padding " << static_cast<int>(padding);
        }
    }
}

TEST(RijndaelContext, AllBlockKeyCombinations) {
    for (size_t block_bits : {size_t(128), size_t(192), size_t(256)}) {
        for (size_t key_bits : {size_t(128), size_t(192), size_t(256)}) {
            EXPECT_TRUE(roundtrip(block_bits, key_bits, SymmetricEncryptionMode::CBC,
                                  SymmetricPaddingScheme::PKCS7, 1))
                << "block=" << block_bits << " key=" << key_bits;
            EXPECT_TRUE(roundtrip(block_bits, key_bits, SymmetricEncryptionMode::CTR,
                                  SymmetricPaddingScheme::Zeros, 1))
                << "block=" << block_bits << " key=" << key_bits;
        }
    }
}

TEST(RijndaelContext, ParallelMatchesSequential) {
    for (SymmetricEncryptionMode mode :
         {SymmetricEncryptionMode::ECB, SymmetricEncryptionMode::CTR,
          SymmetricEncryptionMode::CBC}) {
        std::unique_ptr<crypto::core::SymmetricCipher> cipher_seq =
            std::make_unique<Rijndael>(128);
        std::unique_ptr<crypto::core::SymmetricCipher> cipher_par =
            std::make_unique<Rijndael>(128);
        Bytes                  iv1 = make_iv(16, mode);
        Bytes                  iv2 = make_iv(16, mode);
        SymmetricCipherContext ctx_seq(std::move(cipher_seq), mode,
                                       SymmetricPaddingScheme::PKCS7, iv1);
        SymmetricCipherContext ctx_par(std::move(cipher_par), mode,
                                       SymmetricPaddingScheme::PKCS7, iv2);
        Bytes                  key = make_key(128);
        ctx_seq.set_encryption_key(key);
        ctx_par.set_encryption_key(key);

        Bytes input = make_input(1 + 8 * 16);
        Bytes enc_seq;
        Bytes enc_par;
        ctx_seq.encrypt(input, enc_seq, 1);
        ctx_par.encrypt(input, enc_par, 8);
        EXPECT_EQ(enc_seq, enc_par) << mode_name(mode);
    }
}

TEST(RijndaelContext, ParallelDecryptMatchesSequential) {
    for (SymmetricEncryptionMode mode : {SymmetricEncryptionMode::ECB,
                                         SymmetricEncryptionMode::CTR,
                                         SymmetricEncryptionMode::CBC}) {
        Bytes                                          key = make_key(192);
        std::unique_ptr<crypto::core::SymmetricCipher> cipher_enc =
            std::make_unique<Rijndael>(192);
        Bytes                  iv = make_iv(24, mode);
        SymmetricCipherContext ctx_enc(std::move(cipher_enc), mode,
                                       SymmetricPaddingScheme::PKCS7, iv);
        ctx_enc.set_encryption_key(key);
        Bytes input = make_input(3 * 24 + 1);
        Bytes encrypted;
        ctx_enc.encrypt(input, encrypted, 1);

        Bytes                                          iv_seq = make_iv(24, mode);
        Bytes                                          iv_par = make_iv(24, mode);
        std::unique_ptr<crypto::core::SymmetricCipher> cipher_seq =
            std::make_unique<Rijndael>(192);
        std::unique_ptr<crypto::core::SymmetricCipher> cipher_par =
            std::make_unique<Rijndael>(192);
        SymmetricCipherContext ctx_seq(std::move(cipher_seq), mode,
                                       SymmetricPaddingScheme::PKCS7, iv_seq);
        SymmetricCipherContext ctx_par(std::move(cipher_par), mode,
                                       SymmetricPaddingScheme::PKCS7, iv_par);
        ctx_seq.set_decryption_key(key);
        ctx_par.set_decryption_key(key);

        Bytes dec_seq;
        Bytes dec_par;
        ctx_seq.decrypt(encrypted, dec_seq, 1);
        ctx_par.decrypt(encrypted, dec_par, 8);
        EXPECT_EQ(dec_seq, dec_par) << mode_name(mode);
        EXPECT_EQ(dec_seq, input);
    }
}

TEST(RijndaelContext, DifferentIvGivesDifferentCiphertext) {
    std::unique_ptr<crypto::core::SymmetricCipher> cipher1 =
        std::make_unique<Rijndael>(128);
    std::unique_ptr<crypto::core::SymmetricCipher> cipher2 =
        std::make_unique<Rijndael>(128);
    Bytes                  iv1(16, 0x00);
    Bytes                  iv2(16, 0xFF);
    SymmetricCipherContext ctx1(std::move(cipher1), SymmetricEncryptionMode::CBC,
                                SymmetricPaddingScheme::PKCS7, iv1);
    SymmetricCipherContext ctx2(std::move(cipher2), SymmetricEncryptionMode::CBC,
                                SymmetricPaddingScheme::PKCS7, iv2);
    Bytes                  key = make_key(128);
    ctx1.set_encryption_key(key);
    ctx2.set_encryption_key(key);
    Bytes input = make_input(20);
    Bytes enc1;
    Bytes enc2;
    ctx1.encrypt(input, enc1, 1);
    ctx2.encrypt(input, enc2, 1);
    EXPECT_NE(enc1, enc2);
}

TEST(RijndaelContext, WrongIvSizeThrows) {
    std::unique_ptr<crypto::core::SymmetricCipher> cipher =
        std::make_unique<Rijndael>(128);
    Bytes                  iv(15, 0x00);
    SymmetricCipherContext ctx(std::move(cipher), SymmetricEncryptionMode::CBC,
                               SymmetricPaddingScheme::PKCS7, iv);
    ctx.set_encryption_key(make_key(128));
    Bytes input(16, 0x00);
    Bytes out;
    EXPECT_THROW(ctx.encrypt(input, out, 1), std::invalid_argument);
}

TEST(RijndaelContext, FileEncryptionAsyncRoundtrip) {
    const std::string src = "rijndael_file_test.bin";
    const std::string enc = "rijndael_file_test.enc";
    const std::string dec = "rijndael_file_test.out";

    Bytes         data = make_input(1000);
    std::ofstream src_file(src, std::ios::binary);
    src_file.write(reinterpret_cast<const char *>(data.data()),
                   static_cast<std::streamsize>(data.size()));
    src_file.close();

    for (auto [mode, padding] : {std::pair(SymmetricEncryptionMode::CBC,
                                           SymmetricPaddingScheme::PKCS7),
                                 std::pair(SymmetricEncryptionMode::CTR,
                                           SymmetricPaddingScheme::Zeros),
                                 std::pair(SymmetricEncryptionMode::OFB,
                                           SymmetricPaddingScheme::ISO10126),
                                 std::pair(SymmetricEncryptionMode::CFB,
                                           SymmetricPaddingScheme::AnsiX923)}) {
        std::unique_ptr<crypto::core::SymmetricCipher> cipher =
            std::make_unique<Rijndael>(128);
        Bytes                  iv = make_iv(16, mode);
        SymmetricCipherContext ctx(std::move(cipher), mode, padding, iv);
        Bytes                  key = make_key(128);
        ctx.set_encryption_key(key);
        ctx.set_decryption_key(key);

        auto fut_enc = ctx.encrypt_file(src, enc, 4);
        fut_enc.get();
        auto fut_dec = ctx.decrypt_file(enc, dec, 4);
        fut_dec.get();

        std::ifstream dec_file(dec, std::ios::binary);
        Bytes         recovered((std::istreambuf_iterator<char>(dec_file)),
                                std::istreambuf_iterator<char>());
        EXPECT_EQ(recovered, data) << mode_name(mode) << " padding "
                                   << static_cast<int>(padding);
    }

    std::remove(enc.c_str());
    std::remove(dec.c_str());
    std::remove(src.c_str());
}

TEST(RijndaelContext, ZerosPaddingAddsFullBlockWhenAligned) {
    std::unique_ptr<crypto::core::SymmetricCipher> cipher =
        std::make_unique<Rijndael>(128);
    Bytes                  iv(16, 0x00);
    SymmetricCipherContext ctx(std::move(cipher), SymmetricEncryptionMode::ECB,
                               SymmetricPaddingScheme::Zeros, iv);
    ctx.set_encryption_key(make_key(128));
    Bytes input = make_input(32);
    Bytes encrypted;
    ctx.encrypt(input, encrypted, 1);
    EXPECT_EQ(encrypted.size(), 48u);
}
