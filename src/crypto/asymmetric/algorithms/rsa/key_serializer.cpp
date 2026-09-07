#include "key_serializer.hpp"

#include <fstream>
#include <sstream>
#include <stdexcept>

namespace crypto::rsa {

static constexpr uint8_t TAG_INTEGER = 0x02;
static constexpr uint8_t TAG_SEQUENCE = 0x30;

Bytes KeySerializer::encode_length(size_t length) {
    if (length < 0x80) {
        return {static_cast<uint8_t>(length)};
    }
    Bytes  len_bytes;
    size_t tmp = length;
    while (tmp > 0) {
        len_bytes.insert(len_bytes.begin(), static_cast<uint8_t>(tmp & 0xFF));
        tmp >>= 8;
    }
    Bytes result;
    result.push_back(static_cast<uint8_t>(0x80 | len_bytes.size()));
    result.insert(result.end(), len_bytes.begin(), len_bytes.end());
    return result;
}

Bytes KeySerializer::encode_integer(const mpz_class &value) {
    const size_t bit_count = mpz_sizeinbase(value.get_mpz_t(), 2);
    const size_t byte_count = (bit_count + 7) / 8;
    Bytes        content(byte_count);
    mpz_class    v = value;
    for (size_t i = byte_count; i > 0; --i) {
        content[i - 1] = static_cast<uint8_t>((v.get_ui() & 0xFF));
        v >>= 8;
    }
    if (!content.empty() && (content[0] & 0x80)) {
        content.insert(content.begin(), 0x00);
    }
    Bytes result;
    result.push_back(TAG_INTEGER);
    auto len = encode_length(content.size());
    result.insert(result.end(), len.begin(), len.end());
    result.insert(result.end(), content.begin(), content.end());
    return result;
}

Bytes KeySerializer::encode_sequence(const Bytes &content) {
    Bytes result;
    result.push_back(TAG_SEQUENCE);
    auto len = encode_length(content.size());
    result.insert(result.end(), len.begin(), len.end());
    result.insert(result.end(), content.begin(), content.end());
    return result;
}


void KeySerializer::expect_tag(const Bytes &der, size_t &pos, uint8_t tag) {
    if (pos >= der.size() || der[pos] != tag) {
        throw std::runtime_error("KeySerializer: unexpected ASN.1 tag");
    }
    ++pos;
}

size_t KeySerializer::decode_length(const Bytes &der, size_t &pos) {
    if (pos >= der.size()) {
        throw std::runtime_error("KeySerializer: unexpected end of DER data");
    }
    const uint8_t first = der[pos++];
    if (!(first & 0x80)) {
        return first;
    }
    const size_t num_bytes = first & 0x7F;
    size_t       length = 0;
    for (size_t i = 0; i < num_bytes; ++i) {
        if (pos >= der.size()) {
            throw std::runtime_error("KeySerializer: truncated length");
        }
        length = (length << 8) | der[pos++];
    }
    return length;
}

mpz_class KeySerializer::decode_integer(const Bytes &der, size_t &pos) {
    expect_tag(der, pos, TAG_INTEGER);
    const size_t length = decode_length(der, pos);
    if (pos + length > der.size()) {
        throw std::runtime_error("KeySerializer: integer value truncated");
    }
    mpz_class result(0);
    for (size_t i = 0; i < length; ++i) {
        result = (result << 8) | mpz_class(der[pos++]);
    }
    return result;
}

Bytes KeySerializer::encode_der_public(const KeyPair::PublicKey &key) {
    Bytes content;
    auto  n = encode_integer(key.n);
    auto  e = encode_integer(key.e);
    content.insert(content.end(), n.begin(), n.end());
    content.insert(content.end(), e.begin(), e.end());
    return encode_sequence(content);
}

KeyPair::PublicKey KeySerializer::decode_der_public(const Bytes &der) {
    size_t pos = 0;
    expect_tag(der, pos, TAG_SEQUENCE);
    decode_length(der, pos);
    KeyPair::PublicKey key;
    key.n = decode_integer(der, pos);
    key.e = decode_integer(der, pos);
    return key;
}


Bytes KeySerializer::encode_der_private(const KeyPair::PrivateKey &key) {
    Bytes content;
    auto  append = [&](const Bytes &field) {
        content.insert(content.end(), field.begin(), field.end());
    };
    append(encode_integer(mpz_class(0)));
    append(encode_integer(key.n));
    append(encode_integer(key.e));
    append(encode_integer(key.d));
    append(encode_integer(key.p));
    append(encode_integer(key.q));
    append(encode_integer(key.dp));
    append(encode_integer(key.dq));
    append(encode_integer(key.qp));
    return encode_sequence(content);
}

KeyPair::PrivateKey KeySerializer::decode_der_private(const Bytes &der) {
    size_t pos = 0;
    expect_tag(der, pos, TAG_SEQUENCE);
    decode_length(der, pos);
    decode_integer(der, pos);
    KeyPair::PrivateKey key;
    key.n = decode_integer(der, pos);
    key.e = decode_integer(der, pos);
    key.d = decode_integer(der, pos);
    key.p = decode_integer(der, pos);
    key.q = decode_integer(der, pos);
    key.dp = decode_integer(der, pos);
    key.dq = decode_integer(der, pos);
    key.qp = decode_integer(der, pos);
    return key;
}


static constexpr std::string_view B64_CHARS =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string KeySerializer::base64_encode(const Bytes &data) {
    std::string result;
    result.reserve(((data.size() + 2) / 3) * 4);
    for (size_t i = 0; i < data.size(); i += 3) {
        const uint32_t b0 = data[i];
        const uint32_t b1 = (i + 1 < data.size()) ? data[i + 1] : 0;
        const uint32_t b2 = (i + 2 < data.size()) ? data[i + 2] : 0;
        const uint32_t triple = (b0 << 16) | (b1 << 8) | b2;
        result.push_back(B64_CHARS[(triple >> 18) & 0x3F]);
        result.push_back(B64_CHARS[(triple >> 12) & 0x3F]);
        result.push_back((i + 1 < data.size()) ? B64_CHARS[(triple >> 6) & 0x3F] : '=');
        result.push_back((i + 2 < data.size()) ? B64_CHARS[triple & 0x3F] : '=');
    }
    return result;
}

Bytes KeySerializer::base64_decode(const std::string &data) {
    auto decode_char = [](char c) -> uint8_t {
        if (c >= 'A' && c <= 'Z') {
            return static_cast<uint8_t>(c - 'A');
        }
        if (c >= 'a' && c <= 'z') {
            return static_cast<uint8_t>(c - 'a' + 26);
        }
        if (c >= '0' && c <= '9') {
            return static_cast<uint8_t>(c - '0' + 52);
        }
        if (c == '+') {
            return 62;
        }
        if (c == '/') {
            return 63;
        }
        return 0;
    };
    Bytes result;
    result.reserve((data.size() / 4) * 3);
    for (size_t i = 0; i + 3 < data.size(); i += 4) {
        const uint32_t b0 = decode_char(data[i]);
        const uint32_t b1 = decode_char(data[i + 1]);
        const uint32_t b2 = decode_char(data[i + 2]);
        const uint32_t b3 = decode_char(data[i + 3]);
        const uint32_t triple = (b0 << 18) | (b1 << 12) | (b2 << 6) | b3;
        result.push_back(static_cast<uint8_t>((triple >> 16) & 0xFF));
        if (data[i + 2] != '=') {
            result.push_back(static_cast<uint8_t>((triple >> 8) & 0xFF));
        }
        if (data[i + 3] != '=') {
            result.push_back(static_cast<uint8_t>(triple & 0xFF));
        }
    }
    return result;
}


std::string KeySerializer::to_pem(const Bytes &der, const std::string &label) {
    std::ostringstream oss;
    oss << "-----BEGIN " << label << "-----\n";
    const std::string b64 = base64_encode(der);
    for (size_t i = 0; i < b64.size(); i += 64) {
        oss << b64.substr(i, 64) << '\n';
    }
    oss << "-----END " << label << "-----\n";
    return oss.str();
}

Bytes KeySerializer::from_pem(const std::string &pem, const std::string &label) {
    const std::string header = "-----BEGIN " + label + "-----";
    const std::string footer = "-----END " + label + "-----";
    const size_t      start = pem.find(header);
    const size_t      end = pem.find(footer);
    if (start == std::string::npos || end == std::string::npos) {
        throw std::runtime_error("KeySerializer: PEM label not found: " + label);
    }
    std::string        b64;
    std::istringstream iss(pem.substr(start + header.size(), end - start - header.size()));
    std::string        line;
    while (std::getline(iss, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        b64 += line;
    }
    return base64_decode(b64);
}


void KeySerializer::save_public_key(const KeyPair::PublicKey &key, const std::string &path) {
    const std::string pem = to_pem(encode_der_public(key), "RSA PUBLIC KEY");
    std::ofstream     file(path);
    if (!file) {
        throw std::runtime_error("KeySerializer: cannot open file: " + path);
    }
    file << pem;
}

void KeySerializer::save_private_key(const KeyPair::PrivateKey &key, const std::string &path) {
    const std::string pem = to_pem(encode_der_private(key), "RSA PRIVATE KEY");
    std::ofstream     file(path);
    if (!file) {
        throw std::runtime_error("KeySerializer: cannot open file: " + path);
    }
    file << pem;
}

KeyPair::PublicKey KeySerializer::load_public_key(const std::string &path) {
    std::ifstream file(path);
    if (!file) {
        throw std::runtime_error("KeySerializer: cannot open file: " + path);
    }
    const std::string pem((std::istreambuf_iterator<char>(file)),
                          std::istreambuf_iterator<char>());
    return decode_der_public(from_pem(pem, "RSA PUBLIC KEY"));
}

KeyPair::PrivateKey KeySerializer::load_private_key(const std::string &path) {
    std::ifstream file(path);
    if (!file) {
        throw std::runtime_error("KeySerializer: cannot open file: " + path);
    }
    const std::string pem((std::istreambuf_iterator<char>(file)),
                          std::istreambuf_iterator<char>());
    return decode_der_private(from_pem(pem, "RSA PRIVATE KEY"));
}

} // namespace crypto::rsa
