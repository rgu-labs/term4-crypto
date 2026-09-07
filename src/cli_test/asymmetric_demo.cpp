#include <iostream>
#include <memory>

#include "crypto/asymmetric/algorithms/elgamal/elgamal.hpp"
#include "crypto/asymmetric/algorithms/ntru/ntru.hpp"
#include "crypto/asymmetric/algorithms/rabin/rabin.hpp"
#include "math/miller_rabin_prime_test.hpp"

using namespace crypto;

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

static void demo_elgamal() {
    separator("ElGamal");

    std::cout << "generating key pair (64-bit safe prime)...\n";
    elgamal::ElGamalKeyPair kp = elgamal::KeyGenerator(
                                     std::make_unique<math::MillerRabinPrimeTest>(), 64, 0.9999)
                                     .generate();

    std::cout << "p (bits) = "
              << mpz_sizeinbase(kp.public_key.p.get_mpz_t(), 2) << "\n";
    std::cout << "g        = " << kp.public_key.g << "\n";
    std::cout << "y        = " << kp.public_key.y << "\n";

    elgamal::ElGamal alice(kp);
    elgamal::ElGamal bob(kp.public_key);

    const Bytes message = {'E', 'l', 'G', 'a', 'm', 'a', 'l', '!'};
    std::cout << "plaintext : " << to_hex(message) << "\n";

    const Bytes ciphertext = bob.encrypt(message);
    std::cout << "ciphertext: " << to_hex(ciphertext) << " ("
              << ciphertext.size() << " bytes)\n";

    const Bytes decrypted = alice.decrypt(ciphertext);
    std::cout << "decrypted : " << to_hex(decrypted) << "\n";
    std::cout << "match     : " << (decrypted == message ? "yes" : "NO") << "\n";
}

static void demo_ntru() {
    separator("NTRUEncrypt");

    std::cout << "generating key pair (N=53, p=3, q=547)...\n";
    ntru::NtruKeyPair kp = ntru::KeyGenerator(ntru::NtruParams {}).generate();

    ntru::NTRUEncrypt alice(kp);
    ntru::NTRUEncrypt bob(kp.public_key);

    const Bytes message = {0x4E, 0x54, 0x52, 0x55, 0x21};
    std::cout << "plaintext : " << to_hex(message) << "\n";

    const Bytes ciphertext = bob.encrypt(message);
    std::cout << "ciphertext: " << to_hex(ciphertext) << " ("
              << ciphertext.size() << " bytes)\n";

    const Bytes decrypted = alice.decrypt(ciphertext);
    std::cout << "decrypted : " << to_hex(decrypted) << "\n";
    std::cout << "match     : " << (decrypted == message ? "yes" : "NO") << "\n";
}

static void demo_rabin() {
    separator("Rabin");

    std::cout << "generating key pair (40-bit primes, p,q == 3 mod 4)...\n";
    rabin::RabinKeyPair kp = rabin::KeyGenerator(
                                 std::make_unique<math::MillerRabinPrimeTest>(), 40, 0.9999)
                                 .generate();

    std::cout << "n (bits) = "
              << mpz_sizeinbase(kp.public_key.n.get_mpz_t(), 2) << "\n";

    rabin::Rabin alice(kp);
    rabin::Rabin bob(kp.public_key);

    Bytes message;
    for (unsigned i = 0; i < 200; ++i) {
        message.push_back(static_cast<uint8_t>((i * 13 + 5) & 0xFF));
    }
    std::cout << "plaintext : " << to_hex(message) << " (" << message.size()
              << " bytes)\n";

    const Bytes ciphertext = bob.encrypt(message);
    std::cout << "ciphertext: " << to_hex(ciphertext) << " ("
              << ciphertext.size() << " bytes)\n";

    const Bytes decrypted = alice.decrypt(ciphertext);
    std::cout << "decrypted : " << to_hex(decrypted) << "\n";
    std::cout << "match     : " << (decrypted == message ? "yes" : "NO") << "\n";
}

static void demo_elgamal_signature() {
    separator("ElGamal signature");

    std::cout << "generating key pair (64-bit safe prime)...\n";
    elgamal::ElGamalKeyPair kp = elgamal::KeyGenerator(
                                     std::make_unique<math::MillerRabinPrimeTest>(), 64, 0.9999)
                                     .generate();

    elgamal::ElGamalSigner   signer(kp);
    elgamal::ElGamalVerifier verifier(kp.public_key);

    const Bytes message = {'S', 'i', 'g', 'n', ' ', 'm', 'e', '!', '\0', 0x7F};
    std::cout << "message   : " << to_hex(message) << "\n";

    const elgamal::ElGamalSignature sig = signer.sign(message);
    std::cout << "r         = " << sig.r << "\n";
    std::cout << "s         = " << sig.s << "\n";

    const bool valid = verifier.verify(sig, message);
    std::cout << "valid sig : " << (valid ? "yes" : "NO") << "\n";

    Bytes tampered = message;
    tampered[tampered.size() - 1] ^= 0x01;
    const bool invalid = verifier.verify(sig, tampered);
    std::cout << "tampered  : " << (invalid ? "no (good)" : "NO (bad)") << "\n";
}

int main() {
    std::cout << "Asymmetric crypto demo (lab 12)\n";
    demo_elgamal();
    demo_ntru();
    demo_rabin();
    demo_elgamal_signature();
    std::cout << "\nDone.\n";
    return 0;
}
