#include <fstream>
#include <iterator>
#include <memory>
#include <stdexcept>

#include <gtest/gtest.h>

#include "../src/crypto/symmetric/cipher_context.hpp"
#include "symmetric/mode/modes.hpp"
#include "symmetric/padding/padding.hpp"

using Bytes = crypto::Bytes;

class IdentityCipher final : public crypto::core::SymmetricCipher {
  public:
    explicit IdentityCipher(size_t bs = 8) : m_bs(bs) {}
    void   set_encryption_key(const Bytes &) override {}
    void   set_decryption_key(const Bytes &) override {}
    Bytes  encrypt_block(const Bytes &b) const override { return b; }
    Bytes  decrypt_block(const Bytes &b) const override { return b; }
    size_t block_size() const override { return m_bs; }

  private:
    size_t m_bs;
};

class XorCipher final : public crypto::core::SymmetricCipher {
  public:
    explicit XorCipher(size_t bs = 8) : m_bs(bs) {}
    void  set_encryption_key(const Bytes &) override {}
    void  set_decryption_key(const Bytes &) override {}
    Bytes encrypt_block(const Bytes &b) const override {
        Bytes out(b);
        for (auto &byte : out) {
            byte ^= 0xAA;
        }
        return out;
    }
    Bytes  decrypt_block(const Bytes &b) const override { return encrypt_block(b); }
    size_t block_size() const override { return m_bs; }

  private:
    size_t m_bs;
};

static std::unique_ptr<crypto::core::SymmetricCipher> make_identity(size_t bs = 8) {
    return std::make_unique<IdentityCipher>(bs);
}

static std::unique_ptr<crypto::core::SymmetricCipher> make_xor(size_t bs = 8) {
    return std::make_unique<XorCipher>(bs);
}

TEST(ZerosPadding, ApplyNotAligned) {
    crypto::padding::ZerosPadding p;
    Bytes                         data = {0x01, 0x02, 0x03};
    Bytes                         padded = p.apply(data, 8);
    ASSERT_EQ(padded.size(), 8u);
    ASSERT_EQ(padded[3], 0x00);
    ASSERT_EQ(padded[7], 0x00);
}

TEST(ZerosPadding, ApplyAlreadyAligned) {
    crypto::padding::ZerosPadding p;
    Bytes                         data(8, 0x01);
    Bytes                         padded = p.apply(data, 8);
    ASSERT_EQ(padded.size(), 16u);
}

TEST(ZerosPadding, Roundtrip) {
    crypto::padding::ZerosPadding p;
    Bytes                         data = {0x01, 0x02, 0x03, 0x04, 0x05};
    Bytes                         padded = p.apply(data, 8);
    Bytes                         recovered = p.remove(padded, 8);
    ASSERT_EQ(recovered, data);
}

TEST(ZerosPadding, EmptyInput) {
    crypto::padding::ZerosPadding p;
    Bytes                         data;
    Bytes                         padded = p.apply(data, 8);
    ASSERT_EQ(padded.size(), 8u);
    Bytes recovered = p.remove(padded, 8);
    ASSERT_TRUE(recovered.empty());
}

TEST(ZerosPadding, BlockSizeZeroThrows) {
    crypto::padding::ZerosPadding p;
    ASSERT_THROW(p.apply({0x01}, 0), std::invalid_argument);
    ASSERT_THROW(p.remove({0x01}, 0), std::invalid_argument);
}

TEST(AnsiX923Padding, ApplyNotAligned) {
    crypto::padding::AnsiX923Padding p;
    Bytes                            data = {0x01, 0x02, 0x03};
    Bytes                            padded = p.apply(data, 8);
    ASSERT_EQ(padded.size(), 8u);
    ASSERT_EQ(padded.back(), 5u);
    for (size_t i = 3; i < 7; ++i) {
        ASSERT_EQ(padded[i], 0x00);
    }
}

TEST(AnsiX923Padding, ApplyAlreadyAligned) {
    crypto::padding::AnsiX923Padding p;
    Bytes                            data(8, 0x01);
    Bytes                            padded = p.apply(data, 8);
    ASSERT_EQ(padded.size(), 16u);
    ASSERT_EQ(padded.back(), 8u);
}

TEST(AnsiX923Padding, Roundtrip) {
    crypto::padding::AnsiX923Padding p;
    Bytes                            data = {0xDE, 0xAD, 0xBE, 0xEF};
    Bytes                            padded = p.apply(data, 8);
    Bytes                            recovered = p.remove(padded, 8);
    ASSERT_EQ(recovered, data);
}

TEST(AnsiX923Padding, RoundtripFullBlock) {
    crypto::padding::AnsiX923Padding p;
    Bytes                            data(16, 0xFF);
    Bytes                            padded = p.apply(data, 8);
    ASSERT_EQ(padded.size(), 24u);
    Bytes recovered = p.remove(padded, 8);
    ASSERT_EQ(recovered, data);
}

TEST(AnsiX923Padding, InvalidPaddingThrows) {
    crypto::padding::AnsiX923Padding p;
    Bytes                            bad(8, 0x00);
    bad.back() = 9;
    ASSERT_THROW(p.remove(bad, 8), std::invalid_argument);
}

TEST(AnsiX923Padding, BlockSizeZeroThrows) {
    crypto::padding::AnsiX923Padding p;
    ASSERT_THROW(p.apply({0x01}, 0), std::invalid_argument);
    ASSERT_THROW(p.remove({0x01, 0x01}, 0), std::invalid_argument);
}

TEST(ECB, EncryptDecryptRoundtrip) {
    IdentityCipher    cipher(8);
    crypto::mode::ECB ecb;
    Bytes             input(16, 0x42);
    Bytes             enc, dec;
    ecb.encrypt(cipher, input, enc, 2);
    ecb.decrypt(cipher, enc, dec, 2);
    ASSERT_EQ(dec, input);
}

TEST(ECB, NotBlockAlignedThrows) {
    IdentityCipher    cipher(8);
    crypto::mode::ECB ecb;
    Bytes             bad(7, 0x00);
    Bytes             out;
    ASSERT_THROW(ecb.encrypt(cipher, bad, out, 1), std::invalid_argument);
}

TEST(ECB, ParallelMatchesSequential) {
    XorCipher         cipher(8);
    crypto::mode::ECB ecb;
    Bytes             input;
    for (int i = 0; i < 64; ++i) {
        input.push_back(static_cast<uint8_t>(i));
    }
    Bytes enc1, enc4;
    ecb.encrypt(cipher, input, enc1, 1);
    ecb.encrypt(cipher, input, enc4, 4);
    ASSERT_EQ(enc1, enc4);
}

TEST(CBC, EncryptDecryptRoundtrip) {
    IdentityCipher    cipher(8);
    Bytes             iv(8, 0x01);
    crypto::mode::CBC enc_mode(iv);
    crypto::mode::CBC dec_mode(iv);
    Bytes             input(16, 0xAB);
    Bytes             enc, dec;
    enc_mode.encrypt(cipher, input, enc, 1);
    dec_mode.decrypt(cipher, enc, dec, 2);
    ASSERT_EQ(dec, input);
}

TEST(CBC, DifferentIvGivesDifferentCiphertext) {
    XorCipher         cipher(8);
    Bytes             input(16, 0x55);
    Bytes             iv1(8, 0x00), iv2(8, 0xFF);
    crypto::mode::CBC mode1(iv1), mode2(iv2);
    Bytes             enc1, enc2;
    mode1.encrypt(cipher, input, enc1, 1);
    mode2.encrypt(cipher, input, enc2, 1);
    ASSERT_NE(enc1, enc2);
}

TEST(CBC, WrongIvSizeThrows) {
    IdentityCipher    cipher(8);
    Bytes             bad_iv(5, 0x00);
    crypto::mode::CBC mode(bad_iv);
    Bytes             input(8, 0x00), out;
    ASSERT_THROW(mode.encrypt(cipher, input, out, 1), std::invalid_argument);
}

TEST(CBC, ParallelDecryptMatchesSequential) {
    XorCipher cipher(8);
    Bytes     iv(8, 0xCC);
    Bytes     plain;
    for (int i = 0; i < 32; ++i) {
        plain.push_back(static_cast<uint8_t>(i * 3));
    }
    Bytes enc;
    {
        crypto::mode::CBC m(iv);
        m.encrypt(cipher, plain, enc, 1);
    }
    Bytes dec1, dec4;
    {
        crypto::mode::CBC m(iv);
        m.decrypt(cipher, enc, dec1, 1);
    }
    {
        crypto::mode::CBC m(iv);
        m.decrypt(cipher, enc, dec4, 4);
    }
    ASSERT_EQ(dec1, dec4);
    ASSERT_EQ(dec1, plain);
}

TEST(PCBC, EncryptDecryptRoundtrip) {
    IdentityCipher     cipher(8);
    Bytes              iv(8, 0x33);
    crypto::mode::PCBC enc_mode(iv), dec_mode(iv);
    Bytes              input(24, 0x77);
    Bytes              enc, dec;
    enc_mode.encrypt(cipher, input, enc, 1);
    dec_mode.decrypt(cipher, enc, dec, 1);
    ASSERT_EQ(dec, input);
}

TEST(PCBC, ErrorPropagation) {
    XorCipher          cipher(8);
    Bytes              iv(8, 0x00);
    crypto::mode::PCBC enc_mode(iv);
    Bytes              plain;
    for (int i = 0; i < 24; ++i) {
        plain.push_back(static_cast<uint8_t>(i));
    }
    Bytes enc;
    enc_mode.encrypt(cipher, plain, enc, 1);

    Bytes corrupted = enc;
    corrupted[0] ^= 0xFF;

    Bytes              dec;
    crypto::mode::PCBC dec_mode(iv);
    dec_mode.decrypt(cipher, corrupted, dec, 1);

    Bytes orig_b0(plain.begin(), plain.begin() + 8);
    Bytes dec_b0(dec.begin(), dec.begin() + 8);
    ASSERT_NE(orig_b0, dec_b0);
}

TEST(CipherContext, EcbZerosRoundtrip) {
    crypto::SymmetricCipherContext ctx(make_identity(), crypto::SymmetricEncryptionMode::ECB,
                                       crypto::SymmetricPaddingScheme::Zeros);
    Bytes                          plain = {1, 2, 3, 4, 5};
    Bytes                          enc, dec;
    ctx.encrypt(plain, enc, 1);
    ctx.decrypt(enc, dec, 1);
    ASSERT_EQ(dec, plain);
}

TEST(CipherContext, EcbAnsiX923Roundtrip) {
    crypto::SymmetricCipherContext ctx(make_xor(), crypto::SymmetricEncryptionMode::ECB,
                                       crypto::SymmetricPaddingScheme::AnsiX923);
    Bytes                          plain = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};
    Bytes                          enc, dec;
    ctx.encrypt(plain, enc, 2);
    ctx.decrypt(enc, dec, 2);
    ASSERT_EQ(dec, plain);
}

TEST(CipherContext, CbcZerosRoundtrip) {
    Bytes                          iv(8, 0x5A);
    crypto::SymmetricCipherContext ctx(make_xor(), crypto::SymmetricEncryptionMode::CBC,
                                       crypto::SymmetricPaddingScheme::Zeros, iv);
    Bytes                          plain(13, 0x11);
    Bytes                          enc, dec;
    ctx.encrypt(plain, enc, 1);
    ctx.decrypt(enc, dec, 1);
    ASSERT_EQ(dec, plain);
}

TEST(CipherContext, PcbcAnsiX923Roundtrip) {
    Bytes                          iv(8, 0xF0);
    crypto::SymmetricCipherContext ctx(make_identity(), crypto::SymmetricEncryptionMode::PCBC,
                                       crypto::SymmetricPaddingScheme::AnsiX923, iv);
    Bytes                          plain = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
    Bytes                          enc, dec;
    ctx.encrypt(plain, enc, 1);
    ctx.decrypt(enc, dec, 1);
    ASSERT_EQ(dec, plain);
}

TEST(CipherContext, NullCipherThrows) {
    ASSERT_THROW(
        crypto::SymmetricCipherContext(nullptr, crypto::SymmetricEncryptionMode::ECB,
                                       crypto::SymmetricPaddingScheme::Zeros),
        std::invalid_argument);
}

TEST(CipherContext, CbcEmptyIvUsesZeros) {
    crypto::SymmetricCipherContext ctx_enc(make_xor(), crypto::SymmetricEncryptionMode::CBC,
                                           crypto::SymmetricPaddingScheme::AnsiX923);
    crypto::SymmetricCipherContext ctx_dec(make_xor(), crypto::SymmetricEncryptionMode::CBC,
                                           crypto::SymmetricPaddingScheme::AnsiX923);
    Bytes                          plain = {0xAB, 0xCD, 0xEF};
    Bytes                          enc, dec;
    ctx_enc.encrypt(plain, enc, 1);
    ctx_dec.decrypt(enc, dec, 1);
    ASSERT_EQ(dec, plain);
}

TEST(CipherContext, MultithreadedEcbLargeData) {
    crypto::SymmetricCipherContext ctx(make_xor(), crypto::SymmetricEncryptionMode::ECB,
                                       crypto::SymmetricPaddingScheme::AnsiX923);
    Bytes                          plain(1024);
    for (size_t i = 0; i < plain.size(); ++i) {
        plain[i] = static_cast<uint8_t>(i & 0xFF);
    }
    Bytes enc, dec;
    ctx.encrypt(plain, enc, 8);
    ctx.decrypt(enc, dec, 8);
    ASSERT_EQ(dec, plain);
}

TEST(CipherContext, FileEncryptDecryptRoundtrip) {
    const std::string in_path = "/tmp/ctx_test_plain.bin";
    const std::string enc_path = "/tmp/ctx_test_enc.bin";
    const std::string dec_path = "/tmp/ctx_test_dec.bin";

    Bytes original = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99};
    {
        std::ofstream f(in_path, std::ios::binary);
        f.write(reinterpret_cast<const char *>(original.data()), original.size());
    }

    crypto::SymmetricCipherContext ctx_enc(make_xor(), crypto::SymmetricEncryptionMode::CBC,
                                           crypto::SymmetricPaddingScheme::AnsiX923, Bytes(8, 0x00));
    crypto::SymmetricCipherContext ctx_dec(make_xor(), crypto::SymmetricEncryptionMode::CBC,
                                           crypto::SymmetricPaddingScheme::AnsiX923, Bytes(8, 0x00));

    ctx_enc.encrypt_file(in_path, enc_path, 2).get();
    ctx_dec.decrypt_file(enc_path, dec_path, 2).get();

    std::ifstream result_file(dec_path, std::ios::binary);
    Bytes         recovered(std::istreambuf_iterator<char>(result_file), {});
    ASSERT_EQ(recovered, original);
}

TEST(CipherContext, CfbZerosRoundtrip) {
    Bytes                          iv(8, 0x1A);
    crypto::SymmetricCipherContext ctx_enc(make_xor(), crypto::SymmetricEncryptionMode::CFB,
                                           crypto::SymmetricPaddingScheme::Zeros, iv);
    crypto::SymmetricCipherContext ctx_dec(make_xor(), crypto::SymmetricEncryptionMode::CFB,
                                           crypto::SymmetricPaddingScheme::Zeros, iv);
    Bytes                          plain = {0x01, 0x02, 0x03, 0x04, 0x05};
    Bytes                          enc, dec;
    ctx_enc.encrypt(plain, enc, 1);
    ctx_dec.decrypt(enc, dec, 1);
    ASSERT_EQ(dec, plain);
}

TEST(CipherContext, CfbAnsiX923Roundtrip) {
    Bytes                          iv(8, 0xBB);
    crypto::SymmetricCipherContext ctx_enc(make_identity(), crypto::SymmetricEncryptionMode::CFB,
                                           crypto::SymmetricPaddingScheme::AnsiX923, iv);
    crypto::SymmetricCipherContext ctx_dec(make_identity(), crypto::SymmetricEncryptionMode::CFB,
                                           crypto::SymmetricPaddingScheme::AnsiX923, iv);
    Bytes                          plain(20, 0x55);
    Bytes                          enc, dec;
    ctx_enc.encrypt(plain, enc, 1);
    ctx_dec.decrypt(enc, dec, 1);
    ASSERT_EQ(dec, plain);
}

TEST(CipherContext, CfbEmptyIvUsesZeros) {
    crypto::SymmetricCipherContext ctx_enc(make_xor(), crypto::SymmetricEncryptionMode::CFB,
                                           crypto::SymmetricPaddingScheme::AnsiX923);
    crypto::SymmetricCipherContext ctx_dec(make_xor(), crypto::SymmetricEncryptionMode::CFB,
                                           crypto::SymmetricPaddingScheme::AnsiX923);
    Bytes                          plain = {0xAA, 0xBB, 0xCC};
    Bytes                          enc, dec;
    ctx_enc.encrypt(plain, enc, 1);
    ctx_dec.decrypt(enc, dec, 1);
    ASSERT_EQ(dec, plain);
}

TEST(CipherContext, CfbDifferentIvGivesDifferentCiphertext) {
    Bytes                          iv1(8, 0x00), iv2(8, 0xFF);
    Bytes                          plain(16, 0x42);
    crypto::SymmetricCipherContext ctx1(make_xor(), crypto::SymmetricEncryptionMode::CFB,
                                        crypto::SymmetricPaddingScheme::Zeros, iv1);
    crypto::SymmetricCipherContext ctx2(make_xor(), crypto::SymmetricEncryptionMode::CFB,
                                        crypto::SymmetricPaddingScheme::Zeros, iv2);
    Bytes                          enc1, enc2;
    ctx1.encrypt(plain, enc1, 1);
    ctx2.encrypt(plain, enc2, 1);
    ASSERT_NE(enc1, enc2);
}

TEST(CipherContext, CfbLargeDataRoundtrip) {
    Bytes                          iv(8, 0x77);
    crypto::SymmetricCipherContext ctx_enc(make_xor(), crypto::SymmetricEncryptionMode::CFB,
                                           crypto::SymmetricPaddingScheme::AnsiX923, iv);
    crypto::SymmetricCipherContext ctx_dec(make_xor(), crypto::SymmetricEncryptionMode::CFB,
                                           crypto::SymmetricPaddingScheme::AnsiX923, iv);
    Bytes                          plain(256);
    for (size_t i = 0; i < plain.size(); ++i) {
        plain[i] = static_cast<uint8_t>(i);
    }
    Bytes enc, dec;
    ctx_enc.encrypt(plain, enc, 1);
    ctx_dec.decrypt(enc, dec, 1);
    ASSERT_EQ(dec, plain);
}

TEST(CipherContext, OfbZerosRoundtrip) {
    Bytes                          iv(8, 0x2B);
    crypto::SymmetricCipherContext ctx_enc(make_xor(), crypto::SymmetricEncryptionMode::OFB,
                                           crypto::SymmetricPaddingScheme::Zeros, iv);
    crypto::SymmetricCipherContext ctx_dec(make_xor(), crypto::SymmetricEncryptionMode::OFB,
                                           crypto::SymmetricPaddingScheme::Zeros, iv);
    Bytes                          plain = {0x10, 0x20, 0x30};
    Bytes                          enc, dec;
    ctx_enc.encrypt(plain, enc, 1);
    ctx_dec.decrypt(enc, dec, 1);
    ASSERT_EQ(dec, plain);
}

TEST(CipherContext, OfbAnsiX923Roundtrip) {
    Bytes                          iv(8, 0x44);
    crypto::SymmetricCipherContext ctx_enc(make_identity(), crypto::SymmetricEncryptionMode::OFB,
                                           crypto::SymmetricPaddingScheme::AnsiX923, iv);
    crypto::SymmetricCipherContext ctx_dec(make_identity(), crypto::SymmetricEncryptionMode::OFB,
                                           crypto::SymmetricPaddingScheme::AnsiX923, iv);
    Bytes                          plain(19, 0xAB);
    Bytes                          enc, dec;
    ctx_enc.encrypt(plain, enc, 1);
    ctx_dec.decrypt(enc, dec, 1);
    ASSERT_EQ(dec, plain);
}

TEST(CipherContext, OfbEmptyIvUsesZeros) {
    crypto::SymmetricCipherContext ctx_enc(make_xor(), crypto::SymmetricEncryptionMode::OFB,
                                           crypto::SymmetricPaddingScheme::AnsiX923);
    crypto::SymmetricCipherContext ctx_dec(make_xor(), crypto::SymmetricEncryptionMode::OFB,
                                           crypto::SymmetricPaddingScheme::AnsiX923);
    Bytes                          plain = {0x01, 0x02, 0x03, 0x04};
    Bytes                          enc, dec;
    ctx_enc.encrypt(plain, enc, 1);
    ctx_dec.decrypt(enc, dec, 1);
    ASSERT_EQ(dec, plain);
}

TEST(CipherContext, OfbDifferentIvGivesDifferentCiphertext) {
    Bytes                          iv1(8, 0x00), iv2(8, 0x01);
    Bytes                          plain(16, 0x99);
    crypto::SymmetricCipherContext ctx1(make_xor(), crypto::SymmetricEncryptionMode::OFB,
                                        crypto::SymmetricPaddingScheme::Zeros, iv1);
    crypto::SymmetricCipherContext ctx2(make_xor(), crypto::SymmetricEncryptionMode::OFB,
                                        crypto::SymmetricPaddingScheme::Zeros, iv2);
    Bytes                          enc1, enc2;
    ctx1.encrypt(plain, enc1, 1);
    ctx2.encrypt(plain, enc2, 1);
    ASSERT_NE(enc1, enc2);
}

TEST(CipherContext, OfbEncryptTwiceSamePlaintextSameCiphertext) {
    Bytes                          iv(8, 0x55);
    Bytes                          plain(16, 0x33);
    crypto::SymmetricCipherContext ctx1(make_xor(), crypto::SymmetricEncryptionMode::OFB,
                                        crypto::SymmetricPaddingScheme::Zeros, iv);
    crypto::SymmetricCipherContext ctx2(make_xor(), crypto::SymmetricEncryptionMode::OFB,
                                        crypto::SymmetricPaddingScheme::Zeros, iv);
    Bytes                          enc1, enc2;
    ctx1.encrypt(plain, enc1, 1);
    ctx2.encrypt(plain, enc2, 1);
    ASSERT_EQ(enc1, enc2);
}

TEST(CipherContext, CtrZerosRoundtrip) {
    crypto::SymmetricCipherContext ctx_enc(make_xor(), crypto::SymmetricEncryptionMode::CTR,
                                           crypto::SymmetricPaddingScheme::Zeros);
    crypto::SymmetricCipherContext ctx_dec(make_xor(), crypto::SymmetricEncryptionMode::CTR,
                                           crypto::SymmetricPaddingScheme::Zeros);
    Bytes                          plain = {0xAA, 0xBB, 0xCC, 0xDD};
    Bytes                          enc, dec;
    ctx_enc.encrypt(plain, enc, 1);
    ctx_dec.decrypt(enc, dec, 1);
    ASSERT_EQ(dec, plain);
}

TEST(CipherContext, CtrAnsiX923Roundtrip) {
    crypto::SymmetricCipherContext ctx_enc(make_identity(), crypto::SymmetricEncryptionMode::CTR,
                                           crypto::SymmetricPaddingScheme::AnsiX923);
    crypto::SymmetricCipherContext ctx_dec(make_identity(), crypto::SymmetricEncryptionMode::CTR,
                                           crypto::SymmetricPaddingScheme::AnsiX923);
    Bytes                          plain(17, 0x7F);
    Bytes                          enc, dec;
    ctx_enc.encrypt(plain, enc, 1);
    ctx_dec.decrypt(enc, dec, 1);
    ASSERT_EQ(dec, plain);
}

TEST(CipherContext, CtrParallelMatchesSequential) {
    crypto::SymmetricCipherContext ctx_seq(make_xor(), crypto::SymmetricEncryptionMode::CTR,
                                           crypto::SymmetricPaddingScheme::Zeros);
    crypto::SymmetricCipherContext ctx_par(make_xor(), crypto::SymmetricEncryptionMode::CTR,
                                           crypto::SymmetricPaddingScheme::Zeros);
    Bytes                          plain(256);
    for (size_t i = 0; i < plain.size(); ++i) {
        plain[i] = static_cast<uint8_t>(i);
    }
    Bytes enc_seq, enc_par;
    ctx_seq.encrypt(plain, enc_seq, 1);
    ctx_par.encrypt(plain, enc_par, 4);
    ASSERT_EQ(enc_seq, enc_par);
}

TEST(CipherContext, CtrLargeDataRoundtrip) {
    crypto::SymmetricCipherContext ctx_enc(make_xor(), crypto::SymmetricEncryptionMode::CTR,
                                           crypto::SymmetricPaddingScheme::AnsiX923);
    crypto::SymmetricCipherContext ctx_dec(make_xor(), crypto::SymmetricEncryptionMode::CTR,
                                           crypto::SymmetricPaddingScheme::AnsiX923);
    Bytes                          plain(512);
    for (size_t i = 0; i < plain.size(); ++i) {
        plain[i] = static_cast<uint8_t>(i & 0xFF);
    }
    Bytes enc, dec;
    ctx_enc.encrypt(plain, enc, 4);
    ctx_dec.decrypt(enc, dec, 4);
    ASSERT_EQ(dec, plain);
}

TEST(CipherContext, RandomDeltaZerosRoundtrip) {
    crypto::SymmetricCipherContext ctx_enc(make_identity(), crypto::SymmetricEncryptionMode::RD,
                                           crypto::SymmetricPaddingScheme::Zeros);
    crypto::SymmetricCipherContext ctx_dec(make_identity(), crypto::SymmetricEncryptionMode::RD,
                                           crypto::SymmetricPaddingScheme::Zeros);
    Bytes                          plain = {0x01, 0x02, 0x03, 0x04, 0x05};
    Bytes                          enc, dec;
    ctx_enc.encrypt(plain, enc, 1);
    ctx_dec.decrypt(enc, dec, 1);
    ASSERT_EQ(dec, plain);
}

TEST(CipherContext, RandomDeltaAnsiX923Roundtrip) {
    crypto::SymmetricCipherContext ctx_enc(make_xor(), crypto::SymmetricEncryptionMode::RD,
                                           crypto::SymmetricPaddingScheme::AnsiX923);
    crypto::SymmetricCipherContext ctx_dec(make_xor(), crypto::SymmetricEncryptionMode::RD,
                                           crypto::SymmetricPaddingScheme::AnsiX923);
    Bytes                          plain(13, 0xEE);
    Bytes                          enc, dec;
    ctx_enc.encrypt(plain, enc, 1);
    ctx_dec.decrypt(enc, dec, 1);
    ASSERT_EQ(dec, plain);
}

TEST(CipherContext, RandomDeltaOutputIsLarger) {
    crypto::SymmetricCipherContext ctx(make_identity(), crypto::SymmetricEncryptionMode::RD,
                                       crypto::SymmetricPaddingScheme::Zeros);
    Bytes                          plain(16, 0x42);
    Bytes                          enc;
    ctx.encrypt(plain, enc, 1);
    ASSERT_GT(enc.size(), plain.size());
}

TEST(CipherContext, RandomDeltaTwoEncryptionsDiffer) {
    crypto::SymmetricCipherContext ctx1(make_identity(), crypto::SymmetricEncryptionMode::RD,
                                        crypto::SymmetricPaddingScheme::Zeros);
    crypto::SymmetricCipherContext ctx2(make_identity(), crypto::SymmetricEncryptionMode::RD,
                                        crypto::SymmetricPaddingScheme::Zeros);
    Bytes                          plain(16, 0x42);
    Bytes                          enc1, enc2;
    ctx1.encrypt(plain, enc1, 1);
    ctx2.encrypt(plain, enc2, 1);
    ASSERT_NE(enc1, enc2);
}

TEST(CipherContext, RandomDeltaLargeDataRoundtrip) {
    crypto::SymmetricCipherContext ctx_enc(make_xor(), crypto::SymmetricEncryptionMode::RD,
                                           crypto::SymmetricPaddingScheme::AnsiX923);
    crypto::SymmetricCipherContext ctx_dec(make_xor(), crypto::SymmetricEncryptionMode::RD,
                                           crypto::SymmetricPaddingScheme::AnsiX923);
    Bytes                          plain(128);
    for (size_t i = 0; i < plain.size(); ++i) {
        plain[i] = static_cast<uint8_t>(i * 2);
    }
    Bytes enc, dec;
    ctx_enc.encrypt(plain, enc, 1);
    ctx_dec.decrypt(enc, dec, 1);
    ASSERT_EQ(dec, plain);
}

TEST(CipherContext, CfbFileRoundtrip) {
    const std::string in_path = "/tmp/cfb_plain.bin";
    const std::string enc_path = "/tmp/cfb_enc.bin";
    const std::string dec_path = "/tmp/cfb_dec.bin";

    Bytes original(20);
    for (size_t i = 0; i < original.size(); ++i) {
        original[i] = static_cast<uint8_t>(i + 1);
    }
    {
        std::ofstream f(in_path, std::ios::binary);
        f.write(reinterpret_cast<const char *>(original.data()), original.size());
    }

    Bytes                          iv(8, 0xAB);
    crypto::SymmetricCipherContext ctx_enc(make_xor(), crypto::SymmetricEncryptionMode::CFB,
                                           crypto::SymmetricPaddingScheme::AnsiX923, iv);
    crypto::SymmetricCipherContext ctx_dec(make_xor(), crypto::SymmetricEncryptionMode::CFB,
                                           crypto::SymmetricPaddingScheme::AnsiX923, iv);

    ctx_enc.encrypt_file(in_path, enc_path, 1).get();
    ctx_dec.decrypt_file(enc_path, dec_path, 1).get();

    std::ifstream result_file(dec_path, std::ios::binary);
    Bytes         recovered(std::istreambuf_iterator<char>(result_file), {});
    ASSERT_EQ(recovered, original);
}

TEST(CipherContext, CtrFileRoundtrip) {
    const std::string in_path = "/tmp/ctr_plain.bin";
    const std::string enc_path = "/tmp/ctr_enc.bin";
    const std::string dec_path = "/tmp/ctr_dec.bin";

    Bytes original(32, 0xCC);
    {
        std::ofstream f(in_path, std::ios::binary);
        f.write(reinterpret_cast<const char *>(original.data()), original.size());
    }

    crypto::SymmetricCipherContext ctx_enc(make_xor(), crypto::SymmetricEncryptionMode::CTR,
                                           crypto::SymmetricPaddingScheme::AnsiX923);
    crypto::SymmetricCipherContext ctx_dec(make_xor(), crypto::SymmetricEncryptionMode::CTR,
                                           crypto::SymmetricPaddingScheme::AnsiX923);

    ctx_enc.encrypt_file(in_path, enc_path, 2).get();
    ctx_dec.decrypt_file(enc_path, dec_path, 2).get();

    std::ifstream result_file(dec_path, std::ios::binary);
    Bytes         recovered(std::istreambuf_iterator<char>(result_file), {});
    ASSERT_EQ(recovered, original);
}

TEST(PKCS7Padding, ApplyNotAligned) {
    crypto::padding::PKCS7Padding p;
    Bytes                         data = {0x01, 0x02, 0x03};
    Bytes                         padded = p.apply(data, 8);
    ASSERT_EQ(padded.size(), 8u);
    for (size_t i = 3; i < 8; ++i) {
        ASSERT_EQ(padded[i], 5u);
    }
}

TEST(PKCS7Padding, ApplyAlreadyAligned) {
    crypto::padding::PKCS7Padding p;
    Bytes                         data(8, 0x01);
    Bytes                         padded = p.apply(data, 8);
    ASSERT_EQ(padded.size(), 16u);
    for (size_t i = 8; i < 16; ++i) {
        ASSERT_EQ(padded[i], 8u);
    }
}

TEST(PKCS7Padding, Roundtrip) {
    crypto::padding::PKCS7Padding p;
    Bytes                         data = {0xDE, 0xAD, 0xBE, 0xEF};
    Bytes                         padded = p.apply(data, 8);
    Bytes                         recovered = p.remove(padded, 8);
    ASSERT_EQ(recovered, data);
}

TEST(PKCS7Padding, RoundtripFullBlock) {
    crypto::padding::PKCS7Padding p;
    Bytes                         data(16, 0xFF);
    Bytes                         padded = p.apply(data, 8);
    ASSERT_EQ(padded.size(), 24u);
    Bytes recovered = p.remove(padded, 8);
    ASSERT_EQ(recovered, data);
}

TEST(PKCS7Padding, EmptyInput) {
    crypto::padding::PKCS7Padding p;
    Bytes                         data;
    Bytes                         padded = p.apply(data, 8);
    ASSERT_EQ(padded.size(), 8u);
    for (auto b : padded) {
        ASSERT_EQ(b, 8u);
    }
    Bytes recovered = p.remove(padded, 8);
    ASSERT_TRUE(recovered.empty());
}

TEST(PKCS7Padding, BlockSizeZeroThrows) {
    crypto::padding::PKCS7Padding p;
    ASSERT_THROW(p.apply({0x01}, 0), std::invalid_argument);
    ASSERT_THROW(p.remove({0x01, 0x01}, 0), std::invalid_argument);
}

TEST(PKCS7Padding, BlockSizeOver255Throws) {
    crypto::padding::PKCS7Padding p;
    ASSERT_THROW(p.apply({0x01}, 256), std::invalid_argument);
}

TEST(PKCS7Padding, InvalidPaddingByteThrows) {
    crypto::padding::PKCS7Padding p;
    Bytes                         bad(8, 0x03);
    bad.back() = 0x04;
    ASSERT_THROW(p.remove(bad, 8), std::invalid_argument);
}

TEST(PKCS7Padding, ZeroPadByteThrows) {
    crypto::padding::PKCS7Padding p;
    Bytes                         bad(8, 0x00);
    ASSERT_THROW(p.remove(bad, 8), std::invalid_argument);
}

TEST(PKCS7Padding, PadByteExceedsBlockSizeThrows) {
    crypto::padding::PKCS7Padding p;
    Bytes                         bad(8, 0x00);
    bad.back() = 9;
    ASSERT_THROW(p.remove(bad, 8), std::invalid_argument);
}

TEST(ISO10126Padding, ApplySize) {
    crypto::padding::ISO10126Padding p(42);
    Bytes                            data = {0x01, 0x02, 0x03};
    Bytes                            padded = p.apply(data, 8);
    ASSERT_EQ(padded.size(), 8u);
    ASSERT_EQ(padded.back(), 5u);
}

TEST(ISO10126Padding, ApplyAlreadyAligned) {
    crypto::padding::ISO10126Padding p(42);
    Bytes                            data(8, 0x01);
    Bytes                            padded = p.apply(data, 8);
    ASSERT_EQ(padded.size(), 16u);
    ASSERT_EQ(padded.back(), 8u);
}

TEST(ISO10126Padding, Roundtrip) {
    crypto::padding::ISO10126Padding p(42);
    Bytes                            data = {0xDE, 0xAD, 0xBE, 0xEF};
    Bytes                            padded = p.apply(data, 8);
    Bytes                            recovered = p.remove(padded, 8);
    ASSERT_EQ(recovered, data);
}

TEST(ISO10126Padding, RoundtripFullBlock) {
    crypto::padding::ISO10126Padding p(42);
    Bytes                            data(16, 0xAB);
    Bytes                            padded = p.apply(data, 8);
    ASSERT_EQ(padded.size(), 24u);
    Bytes recovered = p.remove(padded, 8);
    ASSERT_EQ(recovered, data);
}

TEST(ISO10126Padding, EmptyInput) {
    crypto::padding::ISO10126Padding p(42);
    Bytes                            data;
    Bytes                            padded = p.apply(data, 8);
    ASSERT_EQ(padded.size(), 8u);
    ASSERT_EQ(padded.back(), 8u);
    Bytes recovered = p.remove(padded, 8);
    ASSERT_TRUE(recovered.empty());
}

TEST(ISO10126Padding, BlockSizeZeroThrows) {
    crypto::padding::ISO10126Padding p(42);
    ASSERT_THROW(p.apply({0x01}, 0), std::invalid_argument);
    ASSERT_THROW(p.remove({0x01, 0x01}, 0), std::invalid_argument);
}

TEST(ISO10126Padding, BlockSizeOver255Throws) {
    crypto::padding::ISO10126Padding p(42);
    ASSERT_THROW(p.apply({0x01}, 256), std::invalid_argument);
}

TEST(ISO10126Padding, ZeroPadByteThrows) {
    crypto::padding::ISO10126Padding p(42);
    Bytes                            bad(8, 0x00);
    ASSERT_THROW(p.remove(bad, 8), std::invalid_argument);
}

TEST(ISO10126Padding, PadByteExceedsBlockSizeThrows) {
    crypto::padding::ISO10126Padding p(42);
    Bytes                            bad(8, 0x00);
    bad.back() = 9;
    ASSERT_THROW(p.remove(bad, 8), std::invalid_argument);
}

TEST(ISO10126Padding, RandomBytesInPadding) {
    crypto::padding::ISO10126Padding p1(1), p2(2);
    Bytes                            data = {0x01, 0x02};
    Bytes                            padded1 = p1.apply(data, 8);
    Bytes                            padded2 = p2.apply(data, 8);
    ASSERT_NE(padded1, padded2);
}

TEST(ISO10126Padding, DeterministicWithSameSeed) {
    crypto::padding::ISO10126Padding p1(99), p2(99);
    Bytes                            data = {0xAA, 0xBB};
    ASSERT_EQ(p1.apply(data, 8), p2.apply(data, 8));
}

TEST(CipherContext, EcbPKCS7Roundtrip) {
    crypto::SymmetricCipherContext ctx(make_xor(), crypto::SymmetricEncryptionMode::ECB,
                                       crypto::SymmetricPaddingScheme::PKCS7);
    Bytes                          plain = {0x01, 0x02, 0x03, 0x04, 0x05};
    Bytes                          enc, dec;
    ctx.encrypt(plain, enc, 1);
    ctx.decrypt(enc, dec, 1);
    ASSERT_EQ(dec, plain);
}

TEST(CipherContext, CbcPKCS7Roundtrip) {
    Bytes                          iv(8, 0xAA);
    crypto::SymmetricCipherContext ctx_enc(make_xor(), crypto::SymmetricEncryptionMode::CBC,
                                           crypto::SymmetricPaddingScheme::PKCS7, iv);
    crypto::SymmetricCipherContext ctx_dec(make_xor(), crypto::SymmetricEncryptionMode::CBC,
                                           crypto::SymmetricPaddingScheme::PKCS7, iv);
    Bytes                          plain(13, 0x55);
    Bytes                          enc, dec;
    ctx_enc.encrypt(plain, enc, 1);
    ctx_dec.decrypt(enc, dec, 1);
    ASSERT_EQ(dec, plain);
}

TEST(CipherContext, CfbPKCS7Roundtrip) {
    Bytes                          iv(8, 0x12);
    crypto::SymmetricCipherContext ctx_enc(make_identity(), crypto::SymmetricEncryptionMode::CFB,
                                           crypto::SymmetricPaddingScheme::PKCS7, iv);
    crypto::SymmetricCipherContext ctx_dec(make_identity(), crypto::SymmetricEncryptionMode::CFB,
                                           crypto::SymmetricPaddingScheme::PKCS7, iv);
    Bytes                          plain = {0x11, 0x22, 0x33};
    Bytes                          enc, dec;
    ctx_enc.encrypt(plain, enc, 1);
    ctx_dec.decrypt(enc, dec, 1);
    ASSERT_EQ(dec, plain);
}

TEST(CipherContext, OfbPKCS7Roundtrip) {
    Bytes                          iv(8, 0x34);
    crypto::SymmetricCipherContext ctx_enc(make_xor(), crypto::SymmetricEncryptionMode::OFB,
                                           crypto::SymmetricPaddingScheme::PKCS7, iv);
    crypto::SymmetricCipherContext ctx_dec(make_xor(), crypto::SymmetricEncryptionMode::OFB,
                                           crypto::SymmetricPaddingScheme::PKCS7, iv);
    Bytes                          plain(11, 0x7E);
    Bytes                          enc, dec;
    ctx_enc.encrypt(plain, enc, 1);
    ctx_dec.decrypt(enc, dec, 1);
    ASSERT_EQ(dec, plain);
}

TEST(CipherContext, CtrPKCS7Roundtrip) {
    crypto::SymmetricCipherContext ctx_enc(make_xor(), crypto::SymmetricEncryptionMode::CTR,
                                           crypto::SymmetricPaddingScheme::PKCS7);
    crypto::SymmetricCipherContext ctx_dec(make_xor(), crypto::SymmetricEncryptionMode::CTR,
                                           crypto::SymmetricPaddingScheme::PKCS7);
    Bytes                          plain = {0xCA, 0xFE, 0xBA, 0xBE};
    Bytes                          enc, dec;
    ctx_enc.encrypt(plain, enc, 1);
    ctx_dec.decrypt(enc, dec, 1);
    ASSERT_EQ(dec, plain);
}

TEST(CipherContext, EcbISO10126Roundtrip) {
    crypto::SymmetricCipherContext ctx_enc(make_xor(), crypto::SymmetricEncryptionMode::ECB,
                                           crypto::SymmetricPaddingScheme::ISO10126);
    crypto::SymmetricCipherContext ctx_dec(make_xor(), crypto::SymmetricEncryptionMode::ECB,
                                           crypto::SymmetricPaddingScheme::ISO10126);
    Bytes                          plain = {0x01, 0x02, 0x03, 0x04, 0x05};
    Bytes                          enc, dec;
    ctx_enc.encrypt(plain, enc, 1);
    ctx_dec.decrypt(enc, dec, 1);
    ASSERT_EQ(dec, plain);
}

TEST(CipherContext, CbcISO10126Roundtrip) {
    Bytes                          iv(8, 0xBB);
    crypto::SymmetricCipherContext ctx_enc(make_identity(), crypto::SymmetricEncryptionMode::CBC,
                                           crypto::SymmetricPaddingScheme::ISO10126, iv);
    crypto::SymmetricCipherContext ctx_dec(make_identity(), crypto::SymmetricEncryptionMode::CBC,
                                           crypto::SymmetricPaddingScheme::ISO10126, iv);
    Bytes                          plain(10, 0x99);
    Bytes                          enc, dec;
    ctx_enc.encrypt(plain, enc, 1);
    ctx_dec.decrypt(enc, dec, 1);
    ASSERT_EQ(dec, plain);
}

TEST(CipherContext, CfbISO10126Roundtrip) {
    Bytes                          iv(8, 0x56);
    crypto::SymmetricCipherContext ctx_enc(make_xor(), crypto::SymmetricEncryptionMode::CFB,
                                           crypto::SymmetricPaddingScheme::ISO10126, iv);
    crypto::SymmetricCipherContext ctx_dec(make_xor(), crypto::SymmetricEncryptionMode::CFB,
                                           crypto::SymmetricPaddingScheme::ISO10126, iv);
    Bytes                          plain = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    Bytes                          enc, dec;
    ctx_enc.encrypt(plain, enc, 1);
    ctx_dec.decrypt(enc, dec, 1);
    ASSERT_EQ(dec, plain);
}

TEST(CipherContext, OfbISO10126Roundtrip) {
    Bytes                          iv(8, 0x78);
    crypto::SymmetricCipherContext ctx_enc(make_identity(), crypto::SymmetricEncryptionMode::OFB,
                                           crypto::SymmetricPaddingScheme::ISO10126, iv);
    crypto::SymmetricCipherContext ctx_dec(make_identity(), crypto::SymmetricEncryptionMode::OFB,
                                           crypto::SymmetricPaddingScheme::ISO10126, iv);
    Bytes                          plain(15, 0x11);
    Bytes                          enc, dec;
    ctx_enc.encrypt(plain, enc, 1);
    ctx_dec.decrypt(enc, dec, 1);
    ASSERT_EQ(dec, plain);
}

TEST(CipherContext, CtrISO10126Roundtrip) {
    crypto::SymmetricCipherContext ctx_enc(make_xor(), crypto::SymmetricEncryptionMode::CTR,
                                           crypto::SymmetricPaddingScheme::ISO10126);
    crypto::SymmetricCipherContext ctx_dec(make_xor(), crypto::SymmetricEncryptionMode::CTR,
                                           crypto::SymmetricPaddingScheme::ISO10126);
    Bytes                          plain = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60};
    Bytes                          enc, dec;
    ctx_enc.encrypt(plain, enc, 1);
    ctx_dec.decrypt(enc, dec, 1);
    ASSERT_EQ(dec, plain);
}

TEST(CipherContext, RandomDeltaPKCS7Roundtrip) {
    crypto::SymmetricCipherContext ctx_enc(make_identity(), crypto::SymmetricEncryptionMode::RD,
                                           crypto::SymmetricPaddingScheme::PKCS7);
    crypto::SymmetricCipherContext ctx_dec(make_identity(), crypto::SymmetricEncryptionMode::RD,
                                           crypto::SymmetricPaddingScheme::PKCS7);
    Bytes                          plain = {0xDE, 0xAD, 0xBE, 0xEF};
    Bytes                          enc, dec;
    ctx_enc.encrypt(plain, enc, 1);
    ctx_dec.decrypt(enc, dec, 1);
    ASSERT_EQ(dec, plain);
}

TEST(CipherContext, RandomDeltaISO10126Roundtrip) {
    crypto::SymmetricCipherContext ctx_enc(make_xor(), crypto::SymmetricEncryptionMode::RD,
                                           crypto::SymmetricPaddingScheme::ISO10126);
    crypto::SymmetricCipherContext ctx_dec(make_xor(), crypto::SymmetricEncryptionMode::RD,
                                           crypto::SymmetricPaddingScheme::ISO10126);
    Bytes                          plain(7, 0x42);
    Bytes                          enc, dec;
    ctx_enc.encrypt(plain, enc, 1);
    ctx_dec.decrypt(enc, dec, 1);
    ASSERT_EQ(dec, plain);
}
