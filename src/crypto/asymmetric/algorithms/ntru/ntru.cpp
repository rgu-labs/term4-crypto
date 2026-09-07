#include "ntru.hpp"

#include <optional>
#include <random>
#include <stdexcept>

#include "math/utils.hpp"

namespace crypto::ntru {

namespace {

std::vector<mpz_class> to_mpz(const std::vector<int> &v) {
    std::vector<mpz_class> out(v.size());
    for (std::size_t i = 0; i < v.size(); ++i) {
        out[i] = v[i];
    }
    return out;
}

std::vector<mpz_class> reduce_mod(const std::vector<mpz_class> &a,
                                  const mpz_class              &m) {
    std::vector<mpz_class> out(a.size());
    for (std::size_t i = 0; i < a.size(); ++i) {
        mpz_class r = a[i] % m;
        if (r < 0) {
            r += m;
        }
        out[i] = r;
    }
    return out;
}

std::vector<mpz_class> poly_mul_cyclic(const std::vector<mpz_class>   &a,
                                       const std::vector<mpz_class>   &b,
                                       std::size_t                     N,
                                       const std::optional<mpz_class> &m) {
    std::vector<mpz_class> out(N, 0);
    for (std::size_t i = 0; i < a.size(); ++i) {
        for (std::size_t j = 0; j < b.size(); ++j) {
            out[(i + j) % N] += a[i] * b[j];
        }
    }
    if (m) {
        out = reduce_mod(out, *m);
    }
    return out;
}

std::vector<mpz_class> poly_inverse_mod(const std::vector<mpz_class> &a,
                                        std::size_t                   N,
                                        const mpz_class              &m) {
    std::vector<std::vector<mpz_class>> A(N, std::vector<mpz_class>(N + 1, 0));
    for (std::size_t k = 0; k < N; ++k) {
        for (std::size_t j = 0; j < N; ++j) {
            mpz_class coeff = a[(k + N - j) % N] % m;
            if (coeff < 0) {
                coeff += m;
            }
            A[k][j] = coeff;
        }
        A[k][N] = (k == 0) ? mpz_class(1) : mpz_class(0);
    }

    for (std::size_t col = 0; col < N; ++col) {
        std::size_t pivot = col;
        while (pivot < N && (A[pivot][col] % m) == 0) {
            ++pivot;
        }
        if (pivot == N) {
            return {};
        }
        if (pivot != col) {
            std::swap(A[col], A[pivot]);
        }
        const mpz_class val = A[col][col] % m;
        if (val == 0) {
            return {};
        }
        const mpz_class inv_pivot = math::mod_inverse(val, m);
        for (std::size_t c = col; c <= N; ++c) {
            A[col][c] = (A[col][c] * inv_pivot) % m;
        }
        for (std::size_t r = 0; r < N; ++r) {
            if (r == col) {
                continue;
            }
            const mpz_class factor = A[r][col] % m;
            if (factor == 0) {
                continue;
            }
            for (std::size_t c = col; c <= N; ++c) {
                A[r][c] = ((A[r][c] - factor * A[col][c]) % m + m) % m;
            }
        }
    }

    std::vector<mpz_class> g(N, 0);
    for (std::size_t i = 0; i < N; ++i) {
        g[i] = (A[i][N] % m + m) % m;
    }
    return g;
}

std::size_t count_nonzero(const std::vector<mpz_class> &poly) {
    std::size_t count = 0;
    for (const auto &c : poly) {
        if (c != 0) {
            ++count;
        }
    }
    return count;
}

} // namespace

KeyGenerator::KeyGenerator(NtruParams params) : m_params(std::move(params)) {
    if (m_params.N == 0) {
        throw std::invalid_argument("NTRU: N must be positive");
    }
    if (m_params.p <= 1 || m_params.q <= 1) {
        throw std::invalid_argument("NTRU: p and q must be greater than 1");
    }
    if (m_params.q <= m_params.p) {
        throw std::invalid_argument("NTRU: q must be greater than p");
    }
    if (math::gcd(m_params.p, m_params.q) != 1) {
        throw std::invalid_argument("NTRU: p and q must be coprime");
    }
    m_rng.seed(std::random_device {}());
}

std::vector<int> KeyGenerator::random_small_poly() const {
    std::vector<int> poly(m_params.N, 0);
    for (auto &coeff : poly) {
        const std::size_t r = m_rng() % 3;
        coeff = static_cast<int>((r == 0) ? 0 : (r == 1 ? 1 : -1));
    }
    return poly;
}

NtruKeyPair KeyGenerator::generate() const {
    const std::size_t N = m_params.N;
    for (int attempt = 0; attempt < 10000; ++attempt) {
        const std::vector<int> f_int = random_small_poly();
        const std::vector<int> g_int = random_small_poly();
        if (count_nonzero(to_mpz(f_int)) <= 1 ||
            count_nonzero(to_mpz(g_int)) <= 1) {
            continue;
        }

        std::vector<mpz_class> f(N, 0);
        std::vector<mpz_class> g(N, 0);
        for (std::size_t i = 0; i < N; ++i) {
            f[i] = f_int[i];
            g[i] = g_int[i];
        }

        const std::vector<mpz_class> f_p = poly_inverse_mod(f, N, m_params.p);
        const std::vector<mpz_class> f_q = poly_inverse_mod(f, N, m_params.q);
        if (f_p.empty() || f_q.empty()) {
            continue;
        }

        const std::vector<mpz_class> fq_g =
            poly_mul_cyclic(f_q, g, N, m_params.q);
        std::vector<mpz_class> h(N, 0);
        for (std::size_t i = 0; i < N; ++i) {
            h[i] = (m_params.p * fq_g[i]) % m_params.q;
        }

        NtruKeyPair kp;
        kp.public_key = {m_params, h};
        kp.private_key = {m_params, f, f_p};
        return kp;
    }
    throw std::runtime_error("NTRU: failed to generate a valid key pair");
}

NTRUEncrypt::NTRUEncrypt(NtruKeyPair::PublicKey public_key) : m_public_key(std::move(public_key)) {
    m_rng.seed(std::random_device {}());
}

NTRUEncrypt::NTRUEncrypt(NtruKeyPair::PrivateKey private_key) : m_private_key(std::move(private_key)) {
    m_rng.seed(std::random_device {}());
}

NTRUEncrypt::NTRUEncrypt(NtruKeyPair key_pair) : m_public_key(std::move(key_pair.public_key)),
                                                 m_private_key(std::move(key_pair.private_key)) {
    m_rng.seed(std::random_device {}());
}

mpz_class NTRUEncrypt::centered_mod(const mpz_class &value, const mpz_class &q) {
    mpz_class r = value % q;
    if (r < 0) {
        r += q;
    }
    if (r > q / 2) {
        r -= q;
    }
    return r;
}

std::vector<int> NTRUEncrypt::random_blinding() const {
    const std::size_t N = m_public_key ? m_public_key->params.N
                                       : m_private_key->params.N;
    std::vector<int>  r(N, 0);
    for (auto &coeff : r) {
        const std::size_t v = m_rng() % 3;
        coeff = static_cast<int>(v == 0 ? 0 : (v == 1 ? 1 : -1));
    }
    return r;
}

std::vector<mpz_class> NTRUEncrypt::mul_mod(const std::vector<mpz_class> &a,
                                            const std::vector<mpz_class> &b,
                                            std::size_t                   N) {
    return poly_mul_cyclic(a, b, N, std::nullopt);
}

std::vector<mpz_class> NTRUEncrypt::poly_mod(const std::vector<mpz_class> &a,
                                             const mpz_class              &mod,
                                             std::size_t                   N) {
    std::vector<mpz_class> out = a;
    out.resize(N, 0);
    return reduce_mod(out, mod);
}

Bytes NTRUEncrypt::encrypt(const Bytes &plaintext) const {
    if (!m_public_key) {
        throw std::logic_error("NTRUEncrypt::encrypt: no public key");
    }
    const NtruParams &params = m_public_key->params;
    const std::size_t N = params.N;

    std::vector<mpz_class> msg = msg_poly_from_bytes(params, plaintext);

    std::vector<mpz_class> r(N, 0);
    {
        const std::vector<int> r_int = random_blinding();
        for (std::size_t i = 0; i < N; ++i) {
            r[i] = r_int[i];
        }
    }

    const std::vector<mpz_class> r_h =
        poly_mul_cyclic(r, m_public_key->h, N, params.q);
    std::vector<mpz_class> e(N, 0);
    for (std::size_t i = 0; i < N; ++i) {
        e[i] = (r_h[i] + msg[i]) % params.q;
    }

    return ciphertext_from_poly(params, e);
}

Bytes NTRUEncrypt::decrypt(const Bytes &ciphertext) const {
    if (!m_private_key) {
        throw std::logic_error("NTRUEncrypt::decrypt: no private key");
    }
    const NtruParams &params = m_private_key->params;
    const std::size_t N = params.N;

    const std::vector<mpz_class> e = poly_from_ciphertext(params, ciphertext);

    std::vector<mpz_class> a = poly_mul_cyclic(m_private_key->f, e, N, params.q);
    for (std::size_t i = 0; i < N; ++i) {
        a[i] = centered_mod(a[i], params.q);
    }

    const std::vector<mpz_class> m =
        poly_mul_cyclic(m_private_key->f_p, a, N, params.p);

    return bytes_from_msg_poly(params, m);
}

std::vector<mpz_class> NTRUEncrypt::msg_poly_from_bytes(
    const NtruParams &params, const Bytes &bytes) {
    const std::size_t N = params.N;
    mpz_class         value(0);
    for (const auto byte : bytes) {
        value = (value << 8) | mpz_class(byte);
    }
    std::vector<mpz_class> poly(N, 0);
    mpz_class              cur = value;
    for (std::size_t i = 0; i < N; ++i) {
        poly[i] = cur % params.p;
        cur /= params.p;
    }
    if (cur != 0) {
        throw std::invalid_argument(
            "NTRUEncrypt: plaintext too large for parameter N");
    }
    return poly;
}

Bytes NTRUEncrypt::bytes_from_msg_poly(
    const NtruParams &params, const std::vector<mpz_class> &poly) {
    mpz_class value(0);
    for (std::size_t i = poly.size(); i > 0; --i) {
        value = value * params.p + poly[i - 1];
    }
    Bytes     bytes;
    mpz_class cur = value;
    if (cur == 0) {
        return Bytes {0x00};
    }
    while (cur > 0) {
        bytes.insert(bytes.begin(), static_cast<uint8_t>(cur.get_ui() & 0xFF));
        cur >>= 8;
    }
    return bytes;
}

std::vector<mpz_class> NTRUEncrypt::poly_from_ciphertext(
    const NtruParams &params, const Bytes &bytes) {
    const std::size_t N = params.N;
    mpz_class         max_coeff = params.q - 1;
    const std::size_t coeff_bytes =
        (mpz_sizeinbase(max_coeff.get_mpz_t(), 2) + 7) / 8;
    if (bytes.size() != N * coeff_bytes) {
        throw std::invalid_argument(
            "NTRUEncrypt: malformed ciphertext length");
    }
    std::vector<mpz_class> poly(N, 0);
    for (std::size_t i = 0; i < N; ++i) {
        mpz_class coeff(0);
        for (std::size_t b = 0; b < coeff_bytes; ++b) {
            coeff = (coeff << 8) | mpz_class(
                                       bytes[i * coeff_bytes + b]);
        }
        poly[i] = coeff;
    }
    return poly;
}

Bytes NTRUEncrypt::ciphertext_from_poly(
    const NtruParams &params, const std::vector<mpz_class> &poly) {
    const std::size_t N = params.N;
    mpz_class         max_coeff = params.q - 1;
    const std::size_t coeff_bytes =
        (mpz_sizeinbase(max_coeff.get_mpz_t(), 2) + 7) / 8;
    Bytes out;
    out.reserve(N * coeff_bytes);
    for (std::size_t i = 0; i < N; ++i) {
        mpz_class v = poly[i];
        Bytes     part(coeff_bytes, 0);
        for (std::size_t b = coeff_bytes; b > 0; --b) {
            part[b - 1] = static_cast<uint8_t>(v.get_ui() & 0xFF);
            v >>= 8;
        }
        out.insert(out.end(), part.begin(), part.end());
    }
    return out;
}

} // namespace crypto::ntru
