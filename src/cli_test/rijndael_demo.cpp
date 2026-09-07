#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

#include "crypto/symmetric/algorithms/aes/rijndael.hpp"
#include "crypto/symmetric/algorithms/aes/rijndael_sbox.hpp"
#include "crypto/symmetric/cipher_context.hpp"
#include "math/gf2n/gf2n_polynomial.hpp"

using namespace crypto;
using namespace math::gf2n;

static void separator(const std::string &title) {
    std::cout << "\n== " << title << " ==\n";
}

static std::string to_hex(const Bytes &data) {
    static const char *digits = "0123456789ABCDEF";
    std::string        out;
    out.reserve(data.size() * 2);
    for (uint8_t byte : data) {
        out.push_back(digits[byte >> 4]);
        out.push_back(digits[byte & 0x0F]);
    }
    return out;
}

static void print_polynomial(const Gf2nPolynomial &p) {
    std::cout << p.bits();
    if (!p.is_zero()) {
        std::cout << " (deg " << p.degree() << ")";
    }
    std::cout << "\n";
}

static void demo_gf2n() {
    separator("GF(2^n) polynomial arithmetic");

    Gf2nPolynomial a(0b11011);
    Gf2nPolynomial b(0b101);

    std::cout << "a            = ";
    print_polynomial(a);
    std::cout << "b            = ";
    print_polynomial(b);
    std::cout << "a XOR b      = ";
    print_polynomial(a ^ b);

    const Gf2nPolynomial modulus(0x11B);
    std::cout << "a*b mod 0x11B = ";
    print_polynomial(Gf2nPolynomial::mul_mod(a, b, modulus));

    Gf2nPolynomial remainder;
    Gf2nPolynomial quotient = a.divided_by(b, remainder);
    std::cout << "a / b        = ";
    print_polynomial(quotient);
    std::cout << "a % b        = ";
    print_polynomial(remainder);

    const Gf2nPolynomial element(0x53);
    Gf2nPolynomial       inverse = Gf2nPolynomial::inverse(element, modulus);
    std::cout << "inverse(0x53, 0x11B) = ";
    print_polynomial(inverse);
    std::cout << "check 0x53*inv mod 0x11B = ";
    print_polynomial(Gf2nPolynomial::mul_mod(element, inverse, modulus));

    std::cout << "gcd(a, b)    = ";
    print_polynomial(Gf2nPolynomial::gcd(a, b));
    std::cout << "0x11B irreducible: "
              << (Gf2nPolynomial::is_irreducible(modulus) ? "yes" : "no") << "\n";
    std::cout << "0x101 irreducible: "
              << (Gf2nPolynomial::is_irreducible(Gf2nPolynomial(0x101)) ? "yes"
                                                                        : "no")
              << "\n";
}

static void demo_sboxes() {
    separator("Rijndael S-box / InvS-box (modulus 0x11B)");

    auto sbox = aes::build_sbox(0x11B);
    auto inv_sbox = aes::build_inv_sbox(0x11B);

    std::cout << "S-box row 0 (00-0F):";
    for (unsigned i = 0; i < 16; ++i) {
        std::cout << " " << to_hex(Bytes {sbox[i]});
    }
    std::cout << "\n";

    std::cout << "S-box row F (F0-FF):";
    for (unsigned i = 0xF0; i < 0x100; ++i) {
        std::cout << " " << to_hex(Bytes {sbox[i]});
    }
    std::cout << "\n";

    std::cout << "InvS-box[0xED] = " << to_hex(Bytes {inv_sbox[0xED]}) << "\n";
    std::cout << "InvS-box[0x16] = " << to_hex(Bytes {inv_sbox[0x16]}) << "\n";

    auto sbox_alt = aes::build_sbox(0x11D);
    std::cout << "S-box[0x53] under 0x11B: " << to_hex(Bytes {sbox[0x53]}) << "\n";
    std::cout << "S-box[0x53] under 0x11D: " << to_hex(Bytes {sbox_alt[0x53]}) << "\n";
}

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

static const char *padding_name(SymmetricPaddingScheme padding) {
    switch (padding) {
        case SymmetricPaddingScheme::Zeros:
            return "Zeros";
        case SymmetricPaddingScheme::AnsiX923:
            return "ANSI X9.23";
        case SymmetricPaddingScheme::PKCS7:
            return "PKCS7";
        case SymmetricPaddingScheme::ISO10126:
            return "ISO 10126";
    }
    return "?";
}

static Bytes make_iv(size_t block_bytes, SymmetricEncryptionMode mode) {
    size_t size = mode == SymmetricEncryptionMode::CTR ? block_bytes - 8
                                                       : block_bytes;
    Bytes  iv(size);
    for (size_t i = 0; i < size; ++i) {
        iv[i] = static_cast<uint8_t>(i * 0x3D + 0xB7);
    }
    return iv;
}

static void demo_sync(size_t threads) {
    separator("Synchronous byte-array encryption");

    Bytes key = {
        0x10,
        0x32,
        0x54,
        0x76,
        0x98,
        0xBA,
        0xDC,
        0xFE,
        0x01,
        0x23,
        0x45,
        0x67,
        0x89,
        0xAB,
        0xCD,
        0xEF,
    };

    Bytes input = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                   0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                   0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};

    std::cout << "input : " << to_hex(input) << " (" << input.size()
              << " bytes, threads=" << threads << ")\n";

    for (SymmetricEncryptionMode mode : {
             SymmetricEncryptionMode::ECB, SymmetricEncryptionMode::CBC,
             SymmetricEncryptionMode::PCBC, SymmetricEncryptionMode::CFB,
             SymmetricEncryptionMode::OFB, SymmetricEncryptionMode::CTR,
             SymmetricEncryptionMode::RD}) {
        for (SymmetricPaddingScheme padding :
             {SymmetricPaddingScheme::Zeros, SymmetricPaddingScheme::PKCS7,
              SymmetricPaddingScheme::ISO10126, SymmetricPaddingScheme::AnsiX923}) {
            auto                   cipher = std::make_unique<aes::Rijndael>(128);
            Bytes                  iv = make_iv(16, mode);
            SymmetricCipherContext ctx(std::move(cipher), mode, padding, iv);
            ctx.set_encryption_key(key);
            ctx.set_decryption_key(key);

            Bytes encrypted;
            Bytes decrypted;
            ctx.encrypt(input, encrypted, threads);
            ctx.decrypt(encrypted, decrypted, threads);

            std::cout << "[" << mode_name(mode) << " / " << padding_name(padding)
                      << "] size=" << encrypted.size()
                      << " ok=" << (decrypted == input ? "yes" : "NO") << "\n";
        }
    }

    separator("Block/key size combinations");

    for (size_t block_bits : {size_t(128), size_t(192), size_t(256)}) {
        for (size_t key_bits : {size_t(128), size_t(192), size_t(256)}) {
            auto                   cipher = std::make_unique<aes::Rijndael>(block_bits);
            Bytes                  iv = make_iv(block_bits / 8, SymmetricEncryptionMode::CBC);
            SymmetricCipherContext ctx(std::move(cipher), SymmetricEncryptionMode::CBC,
                                       SymmetricPaddingScheme::PKCS7, iv);
            Bytes                  key_kb(key_bits / 8);
            for (size_t i = 0; i < key_kb.size(); ++i) {
                key_kb[i] = static_cast<uint8_t>(i * 0x11 + 0x03);
            }
            ctx.set_encryption_key(key_kb);
            ctx.set_decryption_key(key_kb);

            Bytes plain(block_bits / 8 + 3);
            for (size_t i = 0; i < plain.size(); ++i) {
                plain[i] = static_cast<uint8_t>(i * 7);
            }
            Bytes enc;
            Bytes dec;
            ctx.encrypt(plain, enc, threads);
            ctx.decrypt(enc, dec, threads);
            std::cout << "block=" << block_bits << " key=" << key_bits
                      << " ok=" << (dec == plain ? "yes" : "NO") << "\n";
        }
    }
}

static void demo_async_file(size_t threads) {
    separator("Asynchronous file encryption");

    const std::string source = "rijndael_demo_input.bin";
    const std::string encrypted = "rijndael_demo_output.enc";
    const std::string decrypted = "rijndael_demo_decrypted.bin";

    Bytes plain(1000);
    for (size_t i = 0; i < plain.size(); ++i) {
        plain[i] = static_cast<uint8_t>((i * 31 + 7) & 0xFF);
    }
    {
        std::ofstream out(source, std::ios::binary);
        out.write(reinterpret_cast<const char *>(plain.data()),
                  static_cast<std::streamsize>(plain.size()));
    }

    Bytes key = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    auto                   cipher = std::make_unique<aes::Rijndael>(128);
    Bytes                  iv(16, 0x00);
    SymmetricCipherContext ctx(std::move(cipher), SymmetricEncryptionMode::OFB,
                               SymmetricPaddingScheme::PKCS7, iv);
    ctx.set_encryption_key(key);
    ctx.set_decryption_key(key);

    ctx.encrypt_file(source, encrypted, threads).get();
    ctx.decrypt_file(encrypted, decrypted, threads).get();

    std::ifstream in(decrypted, std::ios::binary);
    Bytes         recovered((std::istreambuf_iterator<char>(in)),
                            std::istreambuf_iterator<char>());

    std::cout << "encrypted file : " << encrypted << " (" << std::filesystem::file_size(encrypted)
              << " bytes)\n";
    std::cout << "decrypted match: " << (recovered == plain ? "yes" : "NO") << "\n";

    std::remove(encrypted.c_str());
    std::remove(decrypted.c_str());
    std::remove(source.c_str());
}

int main(int argc, char **argv) {
    size_t threads = 1;
    if (argc > 1) {
        threads = static_cast<size_t>(std::stoul(argv[1]));
        if (threads == 0) {
            threads = 1;
        }
    }
    std::cout << "Rijndael demo, threads=" << threads << "\n";

    demo_gf2n();
    demo_sboxes();
    demo_sync(threads);
    demo_async_file(threads);

    std::cout << "\nDone.\n";
    return 0;
}
