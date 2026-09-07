#pragma once

#include <cstdint>
#include <string>
#include <vector>

inline std::vector<uint8_t> bits_from_string(const std::string &bitstr) {
    std::vector<uint8_t> bytes;
    size_t               i = 0;
    while (i < bitstr.size()) {
        uint8_t byte = 0;
        for (size_t b = 0; b < 8; b++) {
            if (i + b < bitstr.size() &&
                (bitstr[i + b] == '0' || bitstr[i + b] == '1')) {
                byte |= (bitstr[i + b] - '0') << (7 - b);
            }
        }
        bytes.push_back(byte);
        i += 8;
    }
    return bytes;
}

inline std::string bits_to_string(const std::vector<uint8_t> &bytes) {
    std::string bitstr;
    for (auto b : bytes) {
        for (int i = 7; i >= 0; i--) {
            bitstr.push_back(((b >> i) & 1) + '0');
        }
    }
    return bitstr;
}
