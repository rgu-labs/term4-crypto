#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <string>

#include "crypto/symmetric/algorithms/mars/mars.hpp"
#include "crypto/symmetric/algorithms/twofish/twofish.hpp"
#include "crypto/symmetric/cipher_context.hpp"

using namespace crypto;

static void separator(const std::string &title) {
    std::cout << "\n== " << title << " ==\n";
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

static const char *algo_name(bool twofish) { return twofish ? "Twofish" : "MARS"; }

static void demo_sync(size_t threads) {
    separator("Synchronous byte-array encryption (Twofish & MARS)");

    const bool algs[] = {true, false};
    for (bool twofish : algs) {
        Bytes key = make_key(128);
        Bytes input = make_input(3 * 16 + 3);

        std::cout << "[" << algo_name(twofish) << "] input size=" << input.size()
                  << " threads=" << threads << "\n";

        for (SymmetricEncryptionMode mode :
             {SymmetricEncryptionMode::ECB, SymmetricEncryptionMode::CBC,
              SymmetricEncryptionMode::PCBC, SymmetricEncryptionMode::CFB,
              SymmetricEncryptionMode::OFB, SymmetricEncryptionMode::CTR,
              SymmetricEncryptionMode::RD}) {
            for (SymmetricPaddingScheme padding :
                 {SymmetricPaddingScheme::Zeros, SymmetricPaddingScheme::PKCS7,
                  SymmetricPaddingScheme::ISO10126,
                  SymmetricPaddingScheme::AnsiX923}) {
                std::unique_ptr<core::SymmetricCipher> cipher =
                    twofish ? std::unique_ptr<core::SymmetricCipher>(
                                  std::make_unique<twofish::Twofish>())
                            : std::unique_ptr<core::SymmetricCipher>(
                                  std::make_unique<mars::MARS>());
                Bytes                  iv = make_iv(16, mode);
                SymmetricCipherContext ctx(std::move(cipher), mode, padding, iv);
                ctx.set_encryption_key(key);
                ctx.set_decryption_key(key);

                Bytes encrypted;
                Bytes decrypted;
                ctx.encrypt(input, encrypted, threads);
                ctx.decrypt(encrypted, decrypted, threads);

                std::cout << "  [" << algo_name(twofish) << " " << mode_name(mode)
                          << " / " << padding_name(padding) << "] size="
                          << encrypted.size()
                          << " ok=" << (decrypted == input ? "yes" : "NO") << "\n";
            }
        }
    }
}

static void demo_async_file(size_t threads) {
    separator("Asynchronous file encryption (Twofish & MARS)");

    const std::string source = "twofish_mars_demo_input.bin";
    const std::string encrypted = "twofish_mars_demo_output.enc";
    const std::string decrypted = "twofish_mars_demo_decrypted.bin";

    Bytes plain = make_input(1000);
    {
        std::ofstream out(source, std::ios::binary);
        out.write(reinterpret_cast<const char *>(plain.data()),
                  static_cast<std::streamsize>(plain.size()));
    }

    const bool algs[] = {true, false};
    for (bool twofish : algs) {
        for (auto [mode, padding] :
             {std::pair(SymmetricEncryptionMode::CBC,
                        SymmetricPaddingScheme::PKCS7),
              std::pair(SymmetricEncryptionMode::CTR,
                        SymmetricPaddingScheme::Zeros),
              std::pair(SymmetricEncryptionMode::OFB,
                        SymmetricPaddingScheme::ISO10126),
              std::pair(SymmetricEncryptionMode::CFB,
                        SymmetricPaddingScheme::AnsiX923)}) {
            std::unique_ptr<core::SymmetricCipher> cipher =
                twofish ? std::unique_ptr<core::SymmetricCipher>(
                              std::make_unique<twofish::Twofish>())
                        : std::unique_ptr<core::SymmetricCipher>(
                              std::make_unique<mars::MARS>());
            Bytes                  iv = make_iv(16, mode);
            SymmetricCipherContext ctx(std::move(cipher), mode, padding, iv);
            Bytes                  key = make_key(128);
            ctx.set_encryption_key(key);
            ctx.set_decryption_key(key);

            ctx.encrypt_file(source, encrypted, threads).get();
            ctx.decrypt_file(encrypted, decrypted, threads).get();

            std::ifstream in(decrypted, std::ios::binary);
            Bytes         recovered((std::istreambuf_iterator<char>(in)),
                                    std::istreambuf_iterator<char>());

            std::cout << "  [" << algo_name(twofish) << " " << mode_name(mode)
                      << " / " << padding_name(padding) << "] enc="
                      << std::filesystem::file_size(encrypted) << "B ok="
                      << (recovered == plain ? "yes" : "NO") << "\n";
        }
    }

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
    std::cout << "Twofish/MARS demo, threads=" << threads << "\n";

    demo_sync(threads);
    demo_async_file(threads);

    std::cout << "\nDone.\n";
    return 0;
}
