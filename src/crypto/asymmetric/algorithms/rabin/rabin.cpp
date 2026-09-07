#include "rabin.hpp"

#include <stdexcept>

#include "math/utils.hpp"

namespace crypto::rabin {

Rabin::Rabin(RabinKeyPair::PublicKey public_key) : m_public_key(std::move(public_key)) {}

Rabin::Rabin(RabinKeyPair::PrivateKey private_key) : m_private_key(std::move(private_key)) {}

Rabin::Rabin(RabinKeyPair key_pair) : m_public_key(std::move(key_pair.public_key)),
                                      m_private_key(std::move(key_pair.private_key)) {}

mpz_class Rabin::bytes_to_mpz(const Bytes &bytes) {
    mpz_class result(0);
    for (const auto byte : bytes) {
        result = (result << 8) | mpz_class(byte);
    }
    return result;
}

Bytes Rabin::mpz_to_bytes_fixed(const mpz_class &value, size_t size) {
    Bytes     result(size, 0);
    mpz_class v = value;
    for (size_t i = size; i > 0; --i) {
        result[i - 1] = static_cast<uint8_t>(v.get_ui() & 0xFF);
        v >>= 8;
    }
    return result;
}

static size_t mpz_byte_size(const mpz_class &n) {
    return (mpz_sizeinbase(n.get_mpz_t(), 2) + 7) / 8;
}

mpz_class Rabin::encode_block(const mpz_class &payload,
                              const mpz_class &n,
                              unsigned long    redundancy_bytes) {
    const mpz_class mask = (mpz_class(1) << (redundancy_bytes * 8)) - 1;
    const mpz_class tail = payload & mask;
    const mpz_class block = (payload << (redundancy_bytes * 8)) | tail;
    return (block * block) % n;
}

std::vector<mpz_class> Rabin::crt_roots(const mpz_class &m1,
                                        const mpz_class &m2,
                                        const mpz_class &p,
                                        const mpz_class &q) {
    const mpz_class        n = p * q;
    const mpz_class        q_pinv = math::mod_inverse(q, p);
    const mpz_class        p_qinv = math::mod_inverse(p, q);
    std::vector<mpz_class> roots;
    roots.reserve(4);
    const mpz_class np1 = n - m1;
    const mpz_class np2 = n - m2;
    for (const mpz_class &pm : {mpz_class(m1), mpz_class(np1)}) {
        for (const mpz_class &qm : {mpz_class(m2), mpz_class(np2)}) {
            mpz_class r = (pm * q % n) * q_pinv % n;
            r = (r + (qm * p % n) * p_qinv) % n;
            roots.push_back(r);
        }
    }
    return roots;
}

bool Rabin::decode_padded(const Bytes &data, const mpz_class &n,
                          Bytes &out) const {
    static constexpr unsigned long kRedundancy = 4;
    static constexpr size_t        kLengthBytes = 4;
    const size_t                   n_bytes = mpz_byte_size(n);
    const mpz_class                mask = (mpz_class(1) << (kRedundancy * 8)) - 1;
    const size_t                   max_payload_bytes = n_bytes - kRedundancy - 1;
    if (max_payload_bytes < kLengthBytes) {
        return false;
    }

    Bytes  stream;
    size_t offset = 0;
    while (offset < data.size()) {
        Bytes blk(data.begin() + static_cast<ptrdiff_t>(offset),
                  data.begin() + static_cast<ptrdiff_t>(offset + n_bytes));
        offset += n_bytes;
        mpz_class block = bytes_to_mpz(blk);
        if (block >= n) {
            return false;
        }
        const mpz_class m1 = math::powm(block % n, (m_private_key->p + 1) / 4, m_private_key->p);
        const mpz_class m2 = math::powm(block % n, (m_private_key->q + 1) / 4, m_private_key->q);
        auto            roots = crt_roots(m1, m2, m_private_key->p, m_private_key->q);
        bool            found = false;
        for (const mpz_class &root : roots) {
            const mpz_class payload = root >> (kRedundancy * 8);
            if (payload >= (mpz_class(1) << (max_payload_bytes * 8))) {
                continue;
            }
            if ((root & mask) == (payload & mask)) {
                Bytes pb = mpz_to_bytes_fixed(payload, max_payload_bytes);
                stream.insert(stream.end(), pb.begin(), pb.end());
                found = true;
                break;
            }
        }
        if (!found) {
            return false;
        }
    }
    if (stream.size() < kLengthBytes) {
        return false;
    }
    mpz_class total = 0;
    for (size_t i = 0; i < kLengthBytes; ++i) {
        total = (total << 8) | mpz_class(stream[i]);
    }
    const size_t len = total.get_ui();
    if (stream.size() < kLengthBytes + len) {
        return false;
    }
    out.assign(stream.begin() + static_cast<ptrdiff_t>(kLengthBytes),
               stream.begin() + static_cast<ptrdiff_t>(kLengthBytes + len));
    return true;
}

Bytes Rabin::encode_padded(const Bytes &data, const mpz_class &n) {
    static constexpr unsigned long kRedundancy = 4;
    static constexpr size_t        kLengthBytes = 4;
    const size_t                   n_bytes = mpz_byte_size(n);
    const size_t                   max_payload_bytes = n_bytes - kRedundancy - 1;
    if (max_payload_bytes < kLengthBytes) {
        throw std::invalid_argument(
            "Rabin::encrypt: key size too small for message encoding");
    }
    Bytes        body;
    const size_t body_size = kLengthBytes + data.size();
    body.reserve(body_size);
    Bytes len_bytes = mpz_to_bytes_fixed(mpz_class(data.size()), kLengthBytes);
    body.insert(body.end(), len_bytes.begin(), len_bytes.end());
    body.insert(body.end(), data.begin(), data.end());
    const size_t padded_size =
        ((body_size + max_payload_bytes - 1) / max_payload_bytes) * max_payload_bytes;
    body.resize(padded_size, 0);

    Bytes out;
    out.reserve(padded_size / max_payload_bytes * n_bytes);
    for (size_t offset = 0; offset < padded_size; offset += max_payload_bytes) {
        Bytes     slice(body.begin() + static_cast<ptrdiff_t>(offset),
                        body.begin() + static_cast<ptrdiff_t>(offset + max_payload_bytes));
        mpz_class payload = bytes_to_mpz(slice);
        mpz_class block = encode_block(payload, n, kRedundancy);
        Bytes     enc = mpz_to_bytes_fixed(block, n_bytes);
        out.insert(out.end(), enc.begin(), enc.end());
    }
    return out;
}

Bytes Rabin::encrypt(const Bytes &plaintext) const {
    if (!m_public_key) {
        throw std::logic_error("Rabin::encrypt: no public key");
    }
    return encode_padded(plaintext, m_public_key->n);
}

Bytes Rabin::decrypt(const Bytes &ciphertext) const {
    if (!m_private_key) {
        throw std::logic_error("Rabin::decrypt: no private key");
    }
    if (ciphertext.empty()) {
        throw std::invalid_argument("Rabin::decrypt: empty ciphertext");
    }
    const size_t n_bytes = mpz_byte_size(m_private_key->p * m_private_key->q);
    if (ciphertext.size() % n_bytes != 0) {
        throw std::invalid_argument("Rabin::decrypt: ciphertext length mismatch");
    }
    Bytes out;
    if (!decode_padded(ciphertext, m_private_key->p * m_private_key->q, out)) {
        throw std::runtime_error("Rabin::decrypt: unable to recover message");
    }
    return out;
}

} // namespace crypto::rabin
