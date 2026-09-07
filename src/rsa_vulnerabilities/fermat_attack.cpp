#include "fermat_attack.hpp"

namespace crypto::rsa {
FermatAttackResult fermat_attack(const mpz_class &n, unsigned long max_steps) {
    mpz_class a;
    mpz_sqrt(a.get_mpz_t(), n.get_mpz_t());
    a += 1;

    for (unsigned long step = 0; step < max_steps; ++step) {
        const mpz_class b2 = a * a - n;
        mpz_class       b;
        mpz_sqrt(b.get_mpz_t(), b2.get_mpz_t());
        if (b * b == b2) {
            return {true, a - b, a + b};
        }
        a += 1;
    }
    return {false, 0, 0};
}
} // namespace crypto::rsa
