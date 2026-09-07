#include "rsa.hpp"

#include <stdexcept>

#include "math/utils.hpp"

namespace crypto::rsa {

Rsa::Rsa(KeyPair::PublicKey public_key) : m_public_key(std::move(public_key)) {}

Rsa::Rsa(KeyPair::PrivateKey private_key) : m_private_key(std::move(private_key)) {}

Rsa::Rsa(KeyPair key_pair) : m_public_key(std::move(key_pair.public_key)),
                             m_private_key(std::move(key_pair.private_key)) {}

mpz_class Rsa::bytes_to_mpz(const Bytes &bytes) {
    mpz_class result(0);
    for (const auto byte : bytes) {
        result = (result << 8) | mpz_class(byte);
    }
    return result;
}

Bytes Rsa::mpz_to_bytes(const mpz_class &value, size_t target_size) {
    Bytes     result(target_size, 0);
    mpz_class v = value;
    for (size_t i = target_size; i > 0; --i) {
        result[i - 1] = static_cast<uint8_t>((v.get_ui() & 0xFF));
        v >>= 8;
    }
    return result;
}

Bytes Rsa::encrypt(const Bytes &plaintext) const {
    if (!m_public_key) {
        throw std::logic_error("Rsa::encrypt: no public key");
    }
    const mpz_class m = bytes_to_mpz(plaintext);
    if (m >= m_public_key->n) {
        throw std::invalid_argument("Rsa::encrypt: plaintext too large for key size");
    }
    const mpz_class c = math::powm(m, m_public_key->e, m_public_key->n);
    const size_t    n_bytes = (mpz_sizeinbase(m_public_key->n.get_mpz_t(), 2) + 7) / 8;
    return mpz_to_bytes(c, n_bytes);
}

Bytes Rsa::decrypt(const Bytes &ciphertext) const {
    if (!m_private_key) {
        throw std::logic_error("Rsa::decrypt: no private key");
    }
    const mpz_class c = bytes_to_mpz(ciphertext);
    const mpz_class m = math::powm(c, m_private_key->d, m_private_key->n);
    const size_t    n_bytes = (mpz_sizeinbase(m_private_key->n.get_mpz_t(), 2) + 7) / 8;
    return mpz_to_bytes(m, n_bytes);
}

} // namespace crypto::rsa
