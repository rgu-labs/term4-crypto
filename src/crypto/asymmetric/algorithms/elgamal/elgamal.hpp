
#pragma once

#include <gmpxx.h>
#include <memory>
#include <optional>

#include "crypto/internal/core/asymmetric_cipher.hpp"
#include "math/prime_test.hpp"

namespace crypto::elgamal {

struct ElGamalKeyPair {
    struct PublicKey {
        mpz_class p; // large prime
        mpz_class g; // primitive root mod p
        mpz_class y; // y = g^x mod p
    };

    struct PrivateKey {
        mpz_class p; // large prime
        mpz_class g; // generator
        mpz_class x; // private exponent
    };

    PublicKey  public_key;
    PrivateKey private_key;
};

class KeyGenerator {
  public:
    KeyGenerator(std::unique_ptr<math::IPrimeTest> &&prime_test,
                 mp_bitcnt_t prime_bits, double min_prime_probability);

    ElGamalKeyPair generate() const;

  private:
    mpz_class        generate_prime() const;
    static mpz_class find_generator_for_prime(const mpz_class &p);

    std::unique_ptr<math::IPrimeTest> m_prime_test;
    mp_bitcnt_t                       m_prime_bits;
    double                            m_min_probability;
    mutable gmp_randclass             m_rng;
};

class ElGamal final : public core::AsymmetricCipher {
  public:
    explicit ElGamal(ElGamalKeyPair::PublicKey public_key);
    explicit ElGamal(ElGamalKeyPair::PrivateKey private_key);
    explicit ElGamal(ElGamalKeyPair key_pair);

    Bytes encrypt(const Bytes &plaintext) const override;
    Bytes decrypt(const Bytes &ciphertext) const override;

  private:
    static mpz_class bytes_to_mpz(const Bytes &bytes);
    static mpz_class random_in_range(const mpz_class &p);

    std::optional<ElGamalKeyPair::PublicKey>  m_public_key;
    std::optional<ElGamalKeyPair::PrivateKey> m_private_key;
};

struct ElGamalSignature {
    mpz_class r;
    mpz_class s;
};

class ElGamalSigner {
  public:
    explicit ElGamalSigner(ElGamalKeyPair key_pair);
    ElGamalSignature sign(const Bytes &message) const;

  private:
    ElGamalKeyPair        m_key_pair;
    mutable gmp_randclass m_rng;
};

class ElGamalVerifier {
  public:
    explicit ElGamalVerifier(ElGamalKeyPair::PublicKey public_key);
    bool verify(const ElGamalSignature &signature, const Bytes &message) const;

  private:
    ElGamalKeyPair::PublicKey m_public_key;
};

} // namespace crypto::elgamal
