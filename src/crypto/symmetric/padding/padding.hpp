
#pragma once

#include <crypto/internal/bytes.hpp>

namespace crypto::padding {

class SymmetricPaddingMode {
  public:
    virtual ~SymmetricPaddingMode() = default;
    virtual Bytes apply(const Bytes &data, size_t block_size) const = 0;
    virtual Bytes remove(const Bytes &data, size_t block_size) const = 0;
};

class ZerosPadding final : public SymmetricPaddingMode {
  public:
    Bytes apply(const Bytes &data, size_t block_size) const override;
    Bytes remove(const Bytes &data, size_t block_size) const override;
};

class AnsiX923Padding final : public SymmetricPaddingMode {
  public:
    Bytes apply(const Bytes &data, size_t block_size) const override;
    Bytes remove(const Bytes &data, size_t block_size) const override;
};

class PKCS7Padding final : public SymmetricPaddingMode {
  public:
    Bytes apply(const Bytes &data, size_t block_size) const override;
    Bytes remove(const Bytes &data, size_t block_size) const override;
};

class ISO10126Padding final : public SymmetricPaddingMode {
  public:
    explicit ISO10126Padding(uint64_t seed = 0);
    Bytes apply(const Bytes &data, size_t block_size) const override;
    Bytes remove(const Bytes &data, size_t block_size) const override;

  private:
    uint64_t m_seed;
};

} // namespace crypto::padding
