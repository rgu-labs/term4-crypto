#pragma once

#include "internal/core/feistel_network_wrapper.hpp"
#include "internal/core/feistel_round_function.hpp"
#include "internal/core/key_expansion.hpp"

namespace crypto::des {

class DES final : public core::FeistelNetworkWrapper {
  public:
    explicit DES();

    size_t block_size() const override;

  protected:
    void before_rounds(Bytes &block, bool encrypting) const override;
    void after_rounds(Bytes &block, bool encrypting) const override;

  public:
    class KeyExpansionDES : public core::KeyExpansion {
      public:
        core::RoundKeys expand(const Bytes &key) const override;
    };

    class FeistelRoundFunctionDES : public core::FeistelRoundFunction {
      public:
        Bytes apply(const Bytes &half_block,
                    const Bytes &round_key) const override;
    };

  private:
    core::FeistelNetwork    m_network;
    KeyExpansionDES         m_key_expansion;
    FeistelRoundFunctionDES m_round_function;
};

} // namespace crypto::des
