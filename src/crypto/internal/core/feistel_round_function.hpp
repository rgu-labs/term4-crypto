#pragma once

#include <internal/bytes.hpp>

namespace crypto::core {

class FeistelRoundFunction {
  public:
    virtual ~FeistelRoundFunction() = default;
    virtual Bytes apply(const Bytes &half, const Bytes &roundKey) const = 0;
};
} // namespace crypto::core
