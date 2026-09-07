#pragma once

#include <array>
#include <cstdint>
#include <vector>

namespace crypto::rc4 {

class Encoder final {
  public:
    Encoder(const std::vector<uint8_t> &key = {0});

    void mutate(const std::vector<uint8_t> &key);

    void encode(std::vector<uint8_t> &data);

  private:
    static constexpr size_t S_SIZE = 256;

    std::array<uint8_t, S_SIZE> m_S {};
    size_t                      m_i {};
    size_t                      m_j {};

    void    KSA(const std::vector<uint8_t> &key);
    uint8_t PRGA();
};

} // namespace crypto::rc4
