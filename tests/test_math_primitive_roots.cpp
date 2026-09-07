#include <gtest/gtest.h>
#include <algorithm>

#include "utils.hpp"
#include "math/primitive_roots.hpp"

static bool contains(const std::vector<mpz_class> &v, const mpz_class &x) {
    return std::find(v.begin(), v.end(), x) != v.end();
}

TEST(PrimitiveRootsTest, NoRootsForN1) {
    ASSERT_TRUE(math::primitive_roots(1).empty());
}

TEST(PrimitiveRootsTest, RootsForN2) {
    const auto roots = math::primitive_roots(2);
    ASSERT_EQ(roots.size(), 1u);
    ASSERT_TRUE(contains(roots, mpz_class(1)));
}

TEST(PrimitiveRootsTest, RootsForN4) {
    const auto roots = math::primitive_roots(4);
    ASSERT_EQ(roots.size(), 1u);
    ASSERT_TRUE(contains(roots, mpz_class(3)));
}

TEST(PrimitiveRootsTest, RootsForPrime5) {
    const auto roots = math::primitive_roots(5);
    ASSERT_EQ(roots.size(), 2u);
    ASSERT_TRUE(contains(roots, mpz_class(2)));
    ASSERT_TRUE(contains(roots, mpz_class(3)));
}

TEST(PrimitiveRootsTest, RootsForPrime7) {
    const auto roots = math::primitive_roots(7);
    ASSERT_EQ(roots.size(), 2u);
    ASSERT_TRUE(contains(roots, mpz_class(3)));
    ASSERT_TRUE(contains(roots, mpz_class(5)));
}

TEST(PrimitiveRootsTest, RootsForPrime11) {
    const auto roots = math::primitive_roots(11);
    ASSERT_EQ(roots.size(), 4u);
    for (const auto &r : roots) {
        ASSERT_GE(r, mpz_class(1));
        ASSERT_LT(r, mpz_class(11));
    }
}

TEST(PrimitiveRootsTest, NoRootsForN8) {
    ASSERT_TRUE(math::primitive_roots(8).empty());
}

TEST(PrimitiveRootsTest, NoRootsForN12) {
    ASSERT_TRUE(math::primitive_roots(12).empty());
}

TEST(PrimitiveRootsTest, NoRootsForN15) {
    ASSERT_TRUE(math::primitive_roots(15).empty());
}

TEST(PrimitiveRootsTest, RootsForPrimePower9) {
    const auto roots = math::primitive_roots(9);
    ASSERT_EQ(roots.size(), static_cast<size_t>(math::euler_phi_factorization(math::euler_phi_factorization(9)).get_ui()));
    for (const auto &r : roots) {
        ASSERT_GE(r, mpz_class(1));
        ASSERT_LT(r, mpz_class(9));
    }
}

TEST(PrimitiveRootsTest, RootsForPrimePower27) {
    const auto roots = math::primitive_roots(27);
    ASSERT_FALSE(roots.empty());
    for (const auto &r : roots) {
        ASSERT_GE(r, mpz_class(1));
        ASSERT_LT(r, mpz_class(27));
    }
}

TEST(PrimitiveRootsTest, AllRootsAreActuallyPrimitiveRoots) {
    const mpz_class n = 13;
    const mpz_class phi_n = math::euler_phi_factorization(n);
    const auto      roots = math::primitive_roots(n);
    for (const auto &g : roots) {
        std::set<mpz_class> powers;
        mpz_class           cur = 1;
        for (mpz_class i = 0; i < phi_n; i++) {
            cur = (cur * g) % n;
            powers.insert(cur);
        }
        ASSERT_EQ(static_cast<mpz_class>(powers.size()), phi_n);
    }
}

TEST(PrimitiveRootsTest, CountMatchesPhiPhi) {
    for (int n : {5, 7, 11, 13, 17, 19, 23}) {
        const mpz_class mn(n);
        const mpz_class phi_n = math::euler_phi_factorization(mn);
        const mpz_class phi_phi_n = math::euler_phi_factorization(phi_n);
        const auto      roots = math::primitive_roots(mn);
        ASSERT_EQ(static_cast<mpz_class>(roots.size()), phi_phi_n) << "n=" << n;
    }
}
