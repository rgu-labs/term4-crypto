#pragma once

#include <crypto/internal/bytes.hpp>

namespace crypto::core {
using RoundKeys = std::vector<Bytes>;

class KeyExpansion {
  public:
    virtual ~KeyExpansion() = default;
    virtual RoundKeys expand(const Bytes &key) const = 0;
};
} // namespace crypto::core
