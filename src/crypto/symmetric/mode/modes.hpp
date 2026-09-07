
#pragma once

#include "symmetric/mode/cipher_mode.hpp"

namespace crypto::mode {

class ECB final : public SymmetricCipherMode {
  public:
    void encrypt(core::SymmetricCipher &cipher, const Bytes &input,
                 Bytes &output, size_t threads) override;
    void decrypt(core::SymmetricCipher &cipher, const Bytes &input,
                 Bytes &output, size_t threads) override;

  private:
    static void process(core::SymmetricCipher &cipher, const Bytes &input,
                        Bytes &output, size_t threads, bool encrypting);
};

class CBC final : public SymmetricCipherMode {
  public:
    explicit CBC(Bytes iv = {});
    void encrypt(core::SymmetricCipher &cipher, const Bytes &input,
                 Bytes &output, size_t threads) override;
    void decrypt(core::SymmetricCipher &cipher, const Bytes &input,
                 Bytes &output, size_t threads) override;

  private:
    Bytes get_iv(size_t bs) const;
    Bytes m_iv;
};

class PCBC final : public SymmetricCipherMode {
  public:
    explicit PCBC(Bytes iv = {});
    void encrypt(core::SymmetricCipher &cipher, const Bytes &input,
                 Bytes &output, size_t threads) override;
    void decrypt(core::SymmetricCipher &cipher, const Bytes &input,
                 Bytes &output, size_t threads) override;

  private:
    Bytes get_iv(size_t bs) const;
    Bytes m_iv;
};

class CFB final : public SymmetricCipherMode {
  public:
    explicit CFB(Bytes iv = {});
    void encrypt(core::SymmetricCipher &cipher, const Bytes &input,
                 Bytes &output, size_t threads) override;
    void decrypt(core::SymmetricCipher &cipher, const Bytes &input,
                 Bytes &output, size_t threads) override;

  private:
    Bytes get_iv(size_t bs) const;
    Bytes m_iv;
};

class OFB final : public SymmetricCipherMode {
  public:
    explicit OFB(Bytes iv = {});
    void encrypt(core::SymmetricCipher &cipher, const Bytes &input,
                 Bytes &output, size_t threads) override;
    void decrypt(core::SymmetricCipher &cipher, const Bytes &input,
                 Bytes &output, size_t threads) override;

  private:
    Bytes       get_iv(size_t bs) const;
    static void process(core::SymmetricCipher &cipher, const Bytes &iv,
                        const Bytes &input, Bytes &output);
    Bytes       m_iv;
};

class CTR final : public SymmetricCipherMode {
  public:
    explicit CTR(Bytes nonce = {});
    void encrypt(core::SymmetricCipher &cipher, const Bytes &input,
                 Bytes &output, size_t threads) override;
    void decrypt(core::SymmetricCipher &cipher, const Bytes &input,
                 Bytes &output, size_t threads) override;

  private:
    void         process(core::SymmetricCipher &cipher, const Bytes &input,
                         Bytes &output, size_t threads) const;
    static Bytes make_counter_block(const Bytes &nonce, uint64_t counter,
                                    size_t bs);
    Bytes        m_nonce;
};


class RD final : public SymmetricCipherMode {
  public:
    explicit RD(uint64_t seed = 0);
    void encrypt(core::SymmetricCipher &cipher, const Bytes &input,
                 Bytes &output, size_t threads) override;
    void decrypt(core::SymmetricCipher &cipher, const Bytes &input,
                 Bytes &output, size_t threads) override;

  private:
    uint64_t m_seed;
};

} // namespace crypto::mode
