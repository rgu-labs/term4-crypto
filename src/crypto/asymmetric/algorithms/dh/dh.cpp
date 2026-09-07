#include "dh.hpp"

#include <stdexcept>
#include <gmp.h>

#include "math/utils.hpp"

namespace crypto::dh {

DiffieHellman::DiffieHellman(DhParams params) : m_params(std::move(params)) {
    if (m_params.p < 2) {
        throw std::invalid_argument("DiffieHellman: p must be >= 2");
    }
    if (m_params.g < 2 || m_params.g >= m_params.p) {
        throw std::invalid_argument("DiffieHellman: g must be in [2, p-1]");
    }

    gmp_randstate_t state;
    gmp_randinit_mt(state);

    unsigned long seed;
    FILE         *urandom = fopen("/dev/urandom", "rb");
    if (!urandom) {
        throw std::runtime_error("DiffieHellman: failed to open /dev/urandom");
    }
    if (fread(&seed, sizeof(seed), 1, urandom) != 1) {
        fclose(urandom);
        throw std::runtime_error("DiffieHellman: failed to read /dev/urandom");
    }
    fclose(urandom);

    gmp_randseed_ui(state, seed);

    mpz_class range = m_params.p - 3;
    mpz_urandomm(m_private_key.get_mpz_t(), state, range.get_mpz_t());
    m_private_key += 2;

    gmp_randclear(state);
}

mpz_class DiffieHellman::public_key() const {
    return math::powm(m_params.g, m_private_key, m_params.p);
}

mpz_class DiffieHellman::compute_shared_secret(const mpz_class &other_public_key) const {
    if (other_public_key < 2 || other_public_key >= m_params.p) {
        throw std::invalid_argument("DiffieHellman: other_public_key out of range");
    }
    return math::powm(other_public_key, m_private_key, m_params.p);
}

Bytes DiffieHellman::shared_secret_bytes(const mpz_class &other_public_key, size_t key_size) const {
    const mpz_class secret = compute_shared_secret(other_public_key);

    Bytes     result(key_size, 0);
    mpz_class v = secret;
    for (size_t i = key_size; i > 0; --i) {
        result[i - 1] = static_cast<uint8_t>(v.get_ui() & 0xFF);
        v >>= 8;
    }
    return result;
}

} // namespace crypto::dh
