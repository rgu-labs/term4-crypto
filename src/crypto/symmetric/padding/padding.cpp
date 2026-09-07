#include "symmetric/padding/padding.hpp"

#include <random>
#include <stdexcept>

namespace crypto::padding {

static void validate_block_size(size_t block_size) {
    if (block_size == 0) {
        throw std::invalid_argument("block_size must be > 0");
    }
}

static void validate_data(const Bytes &data, size_t block_size) {
    if (data.empty() || data.size() % block_size != 0) {
        throw std::invalid_argument("data size is not a multiple of block_size");
    }
}

static size_t compute_pad_len(size_t data_size, size_t block_size) {
    size_t pad_len = block_size - (data_size % block_size);
    return pad_len == 0 ? block_size : pad_len;
}

Bytes ZerosPadding::apply(const Bytes &data, size_t block_size) const {
    validate_block_size(block_size);
    size_t pad_len = compute_pad_len(data.size(), block_size);
    Bytes  padded = data;
    padded.insert(padded.end(), pad_len, 0x00);
    return padded;
}

Bytes ZerosPadding::remove(const Bytes &data, size_t block_size) const {
    validate_block_size(block_size);
    validate_data(data, block_size);
    size_t end = data.size();
    while (end > 0 && data[end - 1] == 0x00) {
        --end;
    }
    return Bytes(data.begin(), data.begin() + end);
}

Bytes AnsiX923Padding::apply(const Bytes &data, size_t block_size) const {
    validate_block_size(block_size);
    size_t pad_len = compute_pad_len(data.size(), block_size);
    Bytes  padded = data;
    padded.insert(padded.end(), pad_len - 1, 0x00);
    padded.push_back(static_cast<uint8_t>(pad_len));
    return padded;
}

Bytes AnsiX923Padding::remove(const Bytes &data, size_t block_size) const {
    validate_block_size(block_size);
    validate_data(data, block_size);
    uint8_t pad_len = data.back();
    if (pad_len == 0 || pad_len > block_size || pad_len > data.size()) {
        throw std::invalid_argument("invalid ANSI X.923 padding");
    }
    for (size_t i = data.size() - pad_len; i < data.size() - 1; ++i) {
        if (data[i] != 0x00) {
            throw std::invalid_argument("invalid ANSI X.923 padding: non-zero byte found");
        }
    }
    return Bytes(data.begin(), data.end() - pad_len);
}

Bytes PKCS7Padding::apply(const Bytes &data, size_t block_size) const {
    validate_block_size(block_size);
    if (block_size > 255) {
        throw std::invalid_argument("PKCS7: block_size must be <= 255");
    }
    size_t pad_len = compute_pad_len(data.size(), block_size);
    Bytes  padded = data;
    padded.insert(padded.end(), pad_len, static_cast<uint8_t>(pad_len));
    return padded;
}

Bytes PKCS7Padding::remove(const Bytes &data, size_t block_size) const {
    validate_block_size(block_size);
    validate_data(data, block_size);
    uint8_t pad_len = data.back();
    if (pad_len == 0 || pad_len > block_size || pad_len > data.size()) {
        throw std::invalid_argument("invalid PKCS7 padding");
    }
    for (size_t i = data.size() - pad_len; i < data.size(); ++i) {
        if (data[i] != pad_len) {
            throw std::invalid_argument("invalid PKCS7 padding: inconsistent bytes");
        }
    }
    return Bytes(data.begin(), data.end() - pad_len);
}

ISO10126Padding::ISO10126Padding(uint64_t seed) : m_seed(seed) {}

Bytes ISO10126Padding::apply(const Bytes &data, size_t block_size) const {
    validate_block_size(block_size);
    if (block_size > 255) {
        throw std::invalid_argument("ISO10126: block_size must be <= 255");
    }
    size_t pad_len = compute_pad_len(data.size(), block_size);
    Bytes  padded = data;

    std::mt19937_64                        rng(m_seed != 0 ? m_seed
                                                           : std::mt19937_64::result_type(
                                                                 std::random_device {}()));
    std::uniform_int_distribution<uint8_t> dist(0, 255);

    for (size_t i = 0; i < pad_len - 1; ++i) {
        padded.push_back(dist(rng));
    }
    padded.push_back(static_cast<uint8_t>(pad_len));
    return padded;
}

Bytes ISO10126Padding::remove(const Bytes &data, size_t block_size) const {
    validate_block_size(block_size);
    validate_data(data, block_size);
    uint8_t pad_len = data.back();
    if (pad_len == 0 || pad_len > block_size || pad_len > data.size()) {
        throw std::invalid_argument("invalid ISO 10126 padding");
    }
    return Bytes(data.begin(), data.end() - pad_len);
}

} // namespace crypto::padding
