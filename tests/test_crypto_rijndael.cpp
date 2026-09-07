#include <gtest/gtest.h>
#include <vector>

#include "crypto/symmetric/algorithms/aes/rijndael.hpp"

using crypto::Bytes;
using crypto::aes::Rijndael;

static Bytes hex_to_bytes(const std::string &hex) {
    Bytes result;
    result.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        result.push_back(static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16)));
    }
    return result;
}

static std::string bytes_to_hex(const Bytes &data) {
    static const char *digits = "0123456789ABCDEF";
    std::string        out;
    out.reserve(data.size() * 2);
    for (uint8_t byte : data) {
        out.push_back(digits[byte >> 4]);
        out.push_back(digits[byte & 0x0F]);
    }
    return out;
}

static Bytes make_key(size_t bits) {
    Bytes key(bits / 8, 0x00);
    for (size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<uint8_t>(i * 0x11);
    }
    return key;
}

static Bytes make_block(size_t bits) {
    Bytes block(bits / 8, 0x00);
    for (size_t i = 0; i < block.size(); ++i) {
        block[i] = static_cast<uint8_t>(0xA5 + i);
    }
    return block;
}

struct FipsVector {
    size_t      key_bits;
    size_t      block_bits;
    std::string key;
    std::string plaintext;
    std::string ciphertext;
};

static const FipsVector FIPS_VECTORS[] = {
    {128, 128,
     "000102030405060708090A0B0C0D0E0F",
     "00112233445566778899AABBCCDDEEFF",
     "69C4E0D86A7B0430D8CDB78070B4C55A"},
    {192, 128,
     "000102030405060708090A0B0C0D0E0F1011121314151617",
     "00112233445566778899AABBCCDDEEFF",
     "DDA97CA4864CDFE06EAF70A0EC0D7191"},
    {256, 128,
     "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
     "00112233445566778899AABBCCDDEEFF",
     "8EA2B7CA516745BFEAFC49904B496089"},
};

TEST(Rijndael, Fips197Vectors) {
    for (const FipsVector &v : FIPS_VECTORS) {
        Rijndael cipher(v.block_bits);
        cipher.set_encryption_key(hex_to_bytes(v.key));
        Bytes ct = cipher.encrypt_block(hex_to_bytes(v.plaintext));
        EXPECT_EQ(bytes_to_hex(ct), v.ciphertext);

        cipher.set_decryption_key(hex_to_bytes(v.key));
        Bytes pt = cipher.decrypt_block(ct);
        EXPECT_EQ(bytes_to_hex(pt), v.plaintext);
    }
}

struct ZeroVector {
    size_t      block_bits;
    size_t      key_bits;
    std::string output;
};

static const ZeroVector RIJNDAEL_ZERO_VECTORS[] = {
    {128, 128, "66E94BD4EF8A2C3B884CFA59CA342B2E"},
    {128, 192, "AAE06992ACBF52A3E8F4A96EC9300BD7"},
    {128, 256, "DC95C078A2408989AD48A21492842087"},
    {192, 128, "A92732EB488D8BB98ECD8D95DC9C02E052F250AD369B3849"},
    {192, 192, "C6348BE20007BAC4A8BD62890C8147A2432E760E9A9F9AB8"},
    {192, 256, "17004E806FAEF168FC9CD56F98F070982075C70C8132B945"},
    {256, 128, "A693B288DF7DAE5B1757640276439230DB77C4CD7A871E24D6162E54AF434891"},
    {256, 192, "F927363EF5B3B4984A9EB9109844152EC167F08102644E3F9028070433DF9F2A"},
    {256, 256, "C6227E7740B7E53B5CB77865278EAB0726F62366D9AABAD908936123A1FC8AF3"},
};

TEST(Rijndael, DesignOfRijndaelZeroKeyVectors) {
    for (const ZeroVector &v : RIJNDAEL_ZERO_VECTORS) {
        Rijndael cipher(v.block_bits);
        Bytes    zero_key(v.key_bits / 8, 0x00);
        Bytes    zero_block(v.block_bits / 8, 0x00);
        cipher.set_encryption_key(zero_key);
        Bytes ct = cipher.encrypt_block(zero_block);
        EXPECT_EQ(bytes_to_hex(ct), v.output)
            << "block=" << v.block_bits << " key=" << v.key_bits;
    }
}

TEST(Rijndael, DesignOfRijndaelZeroKeySecondEncryption) {
    for (const ZeroVector &v : RIJNDAEL_ZERO_VECTORS) {
        Rijndael cipher(v.block_bits);
        Bytes    zero_key(v.key_bits / 8, 0x00);
        Bytes    block(v.block_bits / 8, 0x00);
        cipher.set_encryption_key(zero_key);
        cipher.set_decryption_key(zero_key);
        Bytes ct1 = cipher.encrypt_block(block);
        Bytes ct2 = cipher.encrypt_block(ct1);
        EXPECT_NE(ct1, ct2);
        EXPECT_EQ(cipher.decrypt_block(ct1), block);
        EXPECT_EQ(cipher.decrypt_block(ct2), ct1);
    }
}

TEST(Rijndael, RoundtripAllBlockKeyCombinations) {
    for (size_t block_bits : {size_t(128), size_t(192), size_t(256)}) {
        for (size_t key_bits : {size_t(128), size_t(192), size_t(256)}) {
            Rijndael cipher(block_bits);
            Bytes    key = make_key(key_bits);
            Bytes    block = make_block(block_bits);
            cipher.set_encryption_key(key);
            cipher.set_decryption_key(key);
            Bytes ct = cipher.encrypt_block(block);
            Bytes pt = cipher.decrypt_block(ct);
            EXPECT_EQ(pt, block) << "block=" << block_bits << " key=" << key_bits;
        }
    }
}

TEST(Rijndael, DeterministicEncryption) {
    Rijndael cipher(128);
    Bytes    key(16, 0xAB);
    Bytes    block = hex_to_bytes("00112233445566778899AABBCCDDEEFF");
    cipher.set_encryption_key(key);
    EXPECT_EQ(cipher.encrypt_block(block), cipher.encrypt_block(block));
}

TEST(Rijndael, BlockSize) {
    EXPECT_EQ(Rijndael(128).block_size(), 16u);
    EXPECT_EQ(Rijndael(192).block_size(), 24u);
    EXPECT_EQ(Rijndael(256).block_size(), 32u);
}

TEST(Rijndael, InvalidBlockSizeThrows) {
    EXPECT_THROW(Rijndael(160), std::invalid_argument);
    EXPECT_THROW(Rijndael(64), std::invalid_argument);
    EXPECT_THROW(Rijndael(0), std::invalid_argument);
}

TEST(Rijndael, InvalidKeySizeThrows) {
    Rijndael cipher(128);
    EXPECT_THROW(cipher.set_encryption_key(Bytes(15, 0)), std::invalid_argument);
    EXPECT_THROW(cipher.set_encryption_key(Bytes(17, 0)), std::invalid_argument);
    EXPECT_THROW(cipher.set_encryption_key(Bytes(31, 0)), std::invalid_argument);
}

TEST(Rijndael, WrongBlockLengthThrows) {
    Rijndael cipher(128);
    cipher.set_encryption_key(Bytes(16, 0));
    Bytes bad(15, 0x00);
    EXPECT_THROW(cipher.encrypt_block(bad), std::invalid_argument);
    EXPECT_THROW(cipher.decrypt_block(Bytes(17, 0x00)), std::invalid_argument);
    EXPECT_THROW(cipher.encrypt_block(Bytes(24, 0x00)), std::invalid_argument);
}

TEST(Rijndael, EncryptWithoutKeyThrows) {
    Rijndael cipher(128);
    EXPECT_THROW(cipher.encrypt_block(Bytes(16, 0)), std::invalid_argument);
    EXPECT_THROW(cipher.decrypt_block(Bytes(16, 0)), std::invalid_argument);
}

TEST(Rijndael, EncryptDiffersFromInput) {
    Rijndael cipher(192);
    Bytes    key(24, 0x00);
    Bytes    block(24, 0x00);
    cipher.set_encryption_key(key);
    Bytes ct = cipher.encrypt_block(block);
    EXPECT_NE(ct, block);
}

TEST(Rijndael, DifferentKeyGivesDifferentCiphertext) {
    Rijndael cipher(128);
    Bytes    block = hex_to_bytes("00112233445566778899AABBCCDDEEFF");
    cipher.set_encryption_key(Bytes(16, 0x00));
    Bytes ct1 = cipher.encrypt_block(block);
    cipher.set_encryption_key(Bytes(16, 0xFF));
    Bytes ct2 = cipher.encrypt_block(block);
    EXPECT_NE(ct1, ct2);
}
