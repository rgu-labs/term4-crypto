#include <iostream>
#include <filesystem>
#include <fstream>

#include "crypto/asymmetric/algorithms/rsa/rsa.hpp"
#include "math/miller_rabin_prime_test.hpp"

#include "crypto/symmetric/cipher_context.hpp"

#include "crypto/symmetric/algorithms/mars/mars.hpp"
#include "crypto/symmetric/algorithms/twofish/twofish.hpp"

using namespace crypto;


static void log(const std::string &msg) {
    std::cout << "[*] " << msg << "\n";
}

static void separator(const std::string &title) {
    std::cout << "\n─── " << title << " ───\n";
}

static Bytes read_file_local(const std::string &path) {
    std::ifstream f(path, std::ios::binary);
    return {(std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>()};
}

static void write_file_local(const std::string &path, const Bytes &data) {
    std::ofstream f(path, std::ios::binary);
    f.write(reinterpret_cast<const char *>(data.data()), (long)data.size());
}

int main() {
    const std::string input_file = "../src/cli_test/main.cpp";
    const std::string enc_file = "../encrypted.bin";
    const std::string dec_file = "../decrypted.cpp";

    Bytes key = {
        0x10, 0x32, 0x54, 0x76,
        0x98, 0xBA, 0xDC, 0xFE,
        0x01, 0x23, 0x45, 0x67,
        0x89, 0xAB, 0xCD, 0xEF};

    Bytes iv = {
        0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB,
        0xCC, 0xDD, 0xEE, 0xFF};

    separator("Load input file");

    Bytes input = read_file_local(input_file);
    log("input loaded");
    std::cout << "    size: " << input.size() << " bytes\n";

    separator("Cipher selection");

    std::unique_ptr<core::SymmetricCipher> cipher = nullptr;

    cipher = std::make_unique<twofish::Twofish>();

    SymmetricCipherContext ctx(
        std::move(cipher),
        SymmetricEncryptionMode::CBC,
        SymmetricPaddingScheme::PKCS7,
        iv);

    separator("Key setup");

    ctx.set_encryption_key(key);
    ctx.set_decryption_key(key);
    log("key set for encryption/decryption");

    separator("Encrypt file");

    Bytes encrypted;
    ctx.encrypt(input, encrypted, 1);

    write_file_local(enc_file, encrypted);

    log("file encrypted");
    std::cout << "    size: " << encrypted.size() << " bytes\n";

    separator("Decrypt file");

    Bytes decrypted;
    ctx.decrypt(encrypted, decrypted, 1);

    write_file_local(dec_file, decrypted);

    log("file decrypted");
    std::cout << "    size: " << decrypted.size() << " bytes\n";

    separator("Verify");

    if (decrypted == input) {
        log("PASS: decrypted matches original");
    } else {
        log("FAIL: mismatch");
        return 1;
    }

    return 0;
}
