#include <gtest/gtest.h>

#include <fstream>
#include <iterator>
#include <memory>

#include "crypto/symmetric/cipher_context.hpp"
#include "crypto/symmetric/algorithms/twofish/twofish.hpp"

using crypto::Bytes;
using crypto::SymmetricCipherContext;
using crypto::SymmetricEncryptionMode;
using crypto::SymmetricPaddingScheme;
using crypto::twofish::Twofish;

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
        key[i] = static_cast<uint8_t>(i * 0x13 + 0x05);
    }
    return key;
}

static Bytes make_iv(size_t block_bytes, SymmetricEncryptionMode mode) {
    size_t iv_size = mode == SymmetricEncryptionMode::CTR ? block_bytes - 8
                                                          : block_bytes;
    Bytes  iv(iv_size, 0x00);
    for (size_t i = 0; i < iv.size(); ++i) {
        iv[i] = static_cast<uint8_t>(i * 0x2F + 0x91);
    }
    return iv;
}

static Bytes make_input(size_t size) {
    Bytes    input(size);
    uint32_t seed = 0x0BADC0DE;
    for (size_t i = 0; i < size; ++i) {
        seed = seed * 1664525u + 1013904223u;
        input[i] = static_cast<uint8_t>(seed >> 24);
    }
    return input;
}

static bool roundtrip(size_t block_bytes, size_t key_bits,
                      SymmetricEncryptionMode mode,
                      SymmetricPaddingScheme padding, size_t threads) {
    std::unique_ptr<crypto::core::SymmetricCipher> cipher =
        std::make_unique<Twofish>();
    Bytes                  iv = make_iv(block_bytes, mode);
    SymmetricCipherContext ctx(std::move(cipher), mode, padding, iv);
    ctx.set_encryption_key(make_key(key_bits));
    ctx.set_decryption_key(make_key(key_bits));

    Bytes input = make_input(3 * block_bytes + 5);
    Bytes encrypted;
    Bytes decrypted;
    ctx.encrypt(input, encrypted, threads);
    ctx.decrypt(encrypted, decrypted, threads);
    return decrypted == input;
}

TEST(TwofishContext, AllModesAllPaddingsRoundtrip128) {
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
            EXPECT_TRUE(roundtrip(16, 128, mode, padding, 1))
                << mode_name(mode) << " padding " << static_cast<int>(padding);
        }
    }
}

TEST(TwofishContext, AllModesAllPaddingsRoundtrip256) {
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
            EXPECT_TRUE(roundtrip(16, 192, mode, padding, 1))
                << mode_name(mode) << " padding " << static_cast<int>(padding);
        }
    }
}

TEST(TwofishContext, ParallelEncryptMatchesSequential) {
    for (SymmetricEncryptionMode mode :
         {SymmetricEncryptionMode::ECB, SymmetricEncryptionMode::CTR,
          SymmetricEncryptionMode::CBC}) {
        std::unique_ptr<crypto::core::SymmetricCipher> cipher_seq =
            std::make_unique<Twofish>();
        std::unique_ptr<crypto::core::SymmetricCipher> cipher_par =
            std::make_unique<Twofish>();
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

TEST(TwofishContext, ParallelDecryptMatchesSequential) {
    for (SymmetricEncryptionMode mode : {SymmetricEncryptionMode::ECB,
                                         SymmetricEncryptionMode::CTR,
                                         SymmetricEncryptionMode::CBC}) {
        Bytes                                          key = make_key(256);
        std::unique_ptr<crypto::core::SymmetricCipher> cipher_enc =
            std::make_unique<Twofish>();
        Bytes                  iv = make_iv(16, mode);
        SymmetricCipherContext ctx_enc(std::move(cipher_enc), mode,
                                       SymmetricPaddingScheme::PKCS7, iv);
        ctx_enc.set_encryption_key(key);
        Bytes input = make_input(3 * 16 + 1);
        Bytes encrypted;
        ctx_enc.encrypt(input, encrypted, 1);

        Bytes                                          iv_seq = make_iv(16, mode);
        Bytes                                          iv_par = make_iv(16, mode);
        std::unique_ptr<crypto::core::SymmetricCipher> cipher_seq =
            std::make_unique<Twofish>();
        std::unique_ptr<crypto::core::SymmetricCipher> cipher_par =
            std::make_unique<Twofish>();
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

TEST(TwofishContext, FileEncryptionAsyncRoundtrip) {
    const std::string src = "twofish_file_test.bin";
    const std::string enc = "twofish_file_test.enc";
    const std::string dec = "twofish_file_test.out";

    Bytes         data = make_input(1000);
    std::ofstream src_file(src, std::ios::binary);
    src_file.write(reinterpret_cast<const char *>(data.data()),
                   static_cast<std::streamsize>(data.size()));
    src_file.close();

    for (auto [mode, padding] :
         {std::pair(SymmetricEncryptionMode::CBC, SymmetricPaddingScheme::PKCS7),
          std::pair(SymmetricEncryptionMode::CTR, SymmetricPaddingScheme::Zeros),
          std::pair(SymmetricEncryptionMode::OFB, SymmetricPaddingScheme::ISO10126),
          std::pair(SymmetricEncryptionMode::CFB,
                    SymmetricPaddingScheme::AnsiX923)}) {
        std::unique_ptr<crypto::core::SymmetricCipher> cipher =
            std::make_unique<Twofish>();
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

TEST(TwofishContext, DifferentIvGivesDifferentCiphertext) {
    std::unique_ptr<crypto::core::SymmetricCipher> cipher1 =
        std::make_unique<Twofish>();
    std::unique_ptr<crypto::core::SymmetricCipher> cipher2 =
        std::make_unique<Twofish>();
    Bytes                  iv1(16, 0x00);
    Bytes                  iv2(16, 0xFF);
    SymmetricCipherContext ctx1(std::move(cipher1), SymmetricEncryptionMode::CBC,
                                SymmetricPaddingScheme::PKCS7, iv1);
    SymmetricCipherContext ctx2(std::move(cipher2), SymmetricEncryptionMode::CBC,
                                SymmetricPaddingScheme::PKCS7, iv2);
    Bytes                  key = make_key(192);
    ctx1.set_encryption_key(key);
    ctx2.set_encryption_key(key);
    Bytes input = make_input(20);
    Bytes enc1;
    Bytes enc2;
    ctx1.encrypt(input, enc1, 1);
    ctx2.encrypt(input, enc2, 1);
    EXPECT_NE(enc1, enc2);
}
