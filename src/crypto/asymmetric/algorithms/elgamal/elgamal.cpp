#include "elgamal.hpp"

#include <openssl/evp.h>
#include <random>
#include <stdexcept>

#include "math/primitive_roots.hpp"
#include "math/utils.hpp"

namespace crypto::elgamal {

KeyGenerator::KeyGenerator(std::unique_ptr<math::IPrimeTest> &&prime_test,
                           mp_bitcnt_t                         prime_bits,
                           double                              min_prime_probability) : m_prime_test(std::move(prime_test)),
                                                           m_prime_bits(prime_bits),
                                                           m_min_probability(min_prime_probability),
                                                           m_rng(gmp_randinit_default) {
    if (prime_bits < 8) {
        throw std::invalid_argument("prime_bits must be at least 8");
    }
    m_rng.seed(std::random_device {}());
}

mpz_class KeyGenerator::generate_prime() const {
    while (true) {
        mpz_class q = m_rng.get_z_bits(m_prime_bits - 1);
        mpz_setbit(q.get_mpz_t(), m_prime_bits - 2);
        mpz_setbit(q.get_mpz_t(), 0);
        if (!m_prime_test->is_prime(q, m_min_probability)) {
            continue;
        }
        const mpz_class p = 2 * q + 1;
        if (mpz_sizeinbase(p.get_mpz_t(), 2) != m_prime_bits) {
            continue;
        }
        mpz_class r = p % 3;
        if (r == 0) {
            continue;
        }
        if (m_prime_test->is_prime(p, m_min_probability)) {
            return p;
        }
    }
}

mpz_class KeyGenerator::find_generator_for_prime(const mpz_class &p) {
    const mpz_class q = (p - 1) / 2;
    for (mpz_class g(2); g < p; ++g) {
        if (math::powm(g, 2, p) != 1 && math::powm(g, q, p) != 1) {
            return g;
        }
    }
    throw std::runtime_error("ElGamal: failed to find a primitive root");
}

ElGamalKeyPair KeyGenerator::generate() const {
    const mpz_class p = generate_prime();
    const mpz_class g = find_generator_for_prime(p);
    const mpz_class x = m_rng.get_z_range(p - 2) + 1;
    const mpz_class y = math::powm(g, x, p);

    ElGamalKeyPair kp;
    kp.public_key = {p, g, y};
    kp.private_key = {p, g, x};
    return kp;
}

ElGamal::ElGamal(ElGamalKeyPair::PublicKey public_key) : m_public_key(std::move(public_key)) {}

ElGamal::ElGamal(ElGamalKeyPair::PrivateKey private_key) : m_private_key(std::move(private_key)) {}

ElGamal::ElGamal(ElGamalKeyPair key_pair) : m_public_key(std::move(key_pair.public_key)),
                                            m_private_key(std::move(key_pair.private_key)) {}

mpz_class ElGamal::bytes_to_mpz(const Bytes &bytes) {
    mpz_class result(0);
    for (const auto byte : bytes) {
        result = (result << 8) | mpz_class(byte);
    }
    return result;
}

mpz_class ElGamal::random_in_range(const mpz_class &p) {
    gmp_randclass rng(gmp_randinit_default);
    rng.seed(std::random_device {}());
    return rng.get_z_range(p - 2) + 1;
}

static size_t mpz_byte_size(const mpz_class &n) {
    return (mpz_sizeinbase(n.get_mpz_t(), 2) + 7) / 8;
}

static void mpz_to_bytes_fixed(const mpz_class &value, size_t size, Bytes &out) {
    Bytes     part(size, 0);
    mpz_class v = value;
    for (size_t i = size; i > 0; --i) {
        part[i - 1] = static_cast<uint8_t>(v.get_ui() & 0xFF);
        v >>= 8;
    }
    out.insert(out.end(), part.begin(), part.end());
}

static mpz_class mpz_from_bytes(const Bytes &bytes) {
    mpz_class result(0);
    for (const auto byte : bytes) {
        result = (result << 8) | mpz_class(byte);
    }
    return result;
}

static Bytes mpz_to_bytes_trimmed(const mpz_class &value) {
    if (value == 0) {
        return Bytes {0x00};
    }
    Bytes     out;
    mpz_class v = value;
    while (v > 0) {
        out.insert(out.begin(), static_cast<uint8_t>(v.get_ui() & 0xFF));
        v >>= 8;
    }
    return out;
}

Bytes ElGamal::encrypt(const Bytes &plaintext) const {
    if (!m_public_key) {
        throw std::logic_error("ElGamal::encrypt: no public key");
    }
    const mpz_class m = bytes_to_mpz(plaintext);
    if (m < 0 || m >= m_public_key->p) {
        throw std::invalid_argument(
            "ElGamal::encrypt: plaintext too large for group order");
    }
    const mpz_class k = random_in_range(m_public_key->p);
    const mpz_class c1 = math::powm(m_public_key->g, k, m_public_key->p);
    const mpz_class c2 =
        (m * math::powm(m_public_key->y, k, m_public_key->p)) % m_public_key->p;

    const size_t part_size = mpz_byte_size(m_public_key->p);
    Bytes        out;
    out.reserve(2 * part_size);
    mpz_to_bytes_fixed(c1, part_size, out);
    mpz_to_bytes_fixed(c2, part_size, out);
    return out;
}

Bytes ElGamal::decrypt(const Bytes &ciphertext) const {
    if (!m_private_key) {
        throw std::logic_error("ElGamal::decrypt: no private key");
    }
    const size_t part_size = mpz_byte_size(m_private_key->p);
    if (ciphertext.size() != 2 * part_size) {
        throw std::invalid_argument(
            "ElGamal::decrypt: ciphertext length mismatch");
    }

    Bytes           c1_bytes(ciphertext.begin(), ciphertext.begin() + part_size);
    Bytes           c2_bytes(ciphertext.begin() + part_size, ciphertext.end());
    const mpz_class c1 = mpz_from_bytes(c1_bytes);
    const mpz_class c2 = mpz_from_bytes(c2_bytes);

    const mpz_class s = math::powm(c1, m_private_key->x, m_private_key->p);
    const mpz_class s_inv = math::mod_inverse(s, m_private_key->p);
    const mpz_class m = (c2 * s_inv) % m_private_key->p;

    return mpz_to_bytes_trimmed(m);
}

static Bytes sha3_256(const Bytes &data) {
    Bytes        digest(32, 0);
    unsigned int len = 0;
    EVP_MD_CTX  *ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) {
        throw std::runtime_error("ElGamal: failed to allocate hash context");
    }
    if (EVP_DigestInit_ex(ctx, EVP_sha3_256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, data.data(), data.size()) != 1 ||
        EVP_DigestFinal_ex(ctx, digest.data(), &len) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("ElGamal: SHA3-256 hashing failed");
    }
    EVP_MD_CTX_free(ctx);
    (void)len;
    return digest;
}

ElGamalSigner::ElGamalSigner(ElGamalKeyPair key_pair) : m_key_pair(std::move(key_pair)), m_rng(gmp_randinit_default) {
    m_rng.seed(std::random_device {}());
}

ElGamalSignature ElGamalSigner::sign(const Bytes &message) const {
    const mpz_class p = m_key_pair.private_key.p;
    const mpz_class g = m_key_pair.private_key.g;
    const mpz_class x = m_key_pair.private_key.x;

    const Bytes digest = sha3_256(message);
    mpz_class   m(0);
    for (const auto byte : digest) {
        m = (m << 8) | mpz_class(byte);
    }
    m %= (p - 1);

    const mpz_class p_minus_1 = p - 1;
    while (true) {
        mpz_class k = m_rng.get_z_range(p - 2) + 1;
        if (math::gcd(k, p_minus_1) != 1) {
            continue;
        }
        const mpz_class r = math::powm(g, k, p);
        const mpz_class k_inv = math::mod_inverse(k, p_minus_1);
        mpz_class       s = (m - (x * r % p_minus_1)) % p_minus_1;
        if (s < 0) {
            s += p_minus_1;
        }
        s = (s * k_inv) % p_minus_1;
        return {r, s};
    }
}

ElGamalVerifier::ElGamalVerifier(ElGamalKeyPair::PublicKey public_key) : m_public_key(std::move(public_key)) {}

bool ElGamalVerifier::verify(const ElGamalSignature &signature,
                             const Bytes            &message) const {
    const mpz_class p = m_public_key.p;
    if (signature.r <= 0 || signature.r >= p || signature.s < 0 ||
        signature.s >= (p - 1)) {
        return false;
    }

    const Bytes digest = sha3_256(message);
    mpz_class   m(0);
    for (const auto byte : digest) {
        m = (m << 8) | mpz_class(byte);
    }
    m %= (p - 1);

    const mpz_class lhs = math::powm(m_public_key.y, signature.r, p) *
                          math::powm(signature.r, signature.s, p) % p;
    const mpz_class rhs = math::powm(m_public_key.g, m, p);
    return lhs == rhs;
}

} // namespace crypto::elgamal
