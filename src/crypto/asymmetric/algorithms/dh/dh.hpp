
#pragma once

#include <gmpxx.h>

#include "dh_params.hpp"
#include "crypto/internal/bytes.hpp"

namespace crypto::dh {

class DiffieHellman {
  public:
    explicit DiffieHellman(DhParams params);

    mpz_class public_key() const;
    mpz_class compute_shared_secret(const mpz_class &other_public_key) const;

    Bytes shared_secret_bytes(const mpz_class &other_public_key, size_t key_size) const;

  private:
    DhParams  m_params;
    mpz_class m_private_key;
};

} // namespace crypto::dh
