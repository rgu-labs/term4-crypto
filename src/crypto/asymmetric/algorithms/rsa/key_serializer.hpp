#pragma once

#include <string>
#include "key_generator.hpp"
#include "crypto/internal/bytes.hpp"

namespace crypto::rsa {

class KeySerializer {
  public:
    static void save_public_key(const KeyPair::PublicKey &key, const std::string &path);
    static void save_private_key(const KeyPair::PrivateKey &key, const std::string &path);

    static KeyPair::PublicKey  load_public_key(const std::string &path);
    static KeyPair::PrivateKey load_private_key(const std::string &path);

  private:
    static Bytes encode_der_public(const KeyPair::PublicKey &key);
    static Bytes encode_der_private(const KeyPair::PrivateKey &key);

    static KeyPair::PublicKey  decode_der_public(const Bytes &der);
    static KeyPair::PrivateKey decode_der_private(const Bytes &der);

    static Bytes encode_integer(const mpz_class &value);
    static Bytes encode_sequence(const Bytes &content);
    static Bytes encode_length(size_t length);

    static mpz_class decode_integer(const Bytes &der, size_t &pos);
    static size_t    decode_length(const Bytes &der, size_t &pos);
    static void      expect_tag(const Bytes &der, size_t &pos, uint8_t tag);

    static std::string to_pem(const Bytes &der, const std::string &label);
    static Bytes       from_pem(const std::string &pem, const std::string &label);

    static std::string base64_encode(const Bytes &data);
    static Bytes       base64_decode(const std::string &data);
};

} // namespace crypto::rsa
