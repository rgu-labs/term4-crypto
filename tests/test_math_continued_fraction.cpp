#include "math/continued_fraction.hpp"
#include <gmpxx.h>
#include <gtest/gtest.h>

TEST(ToContinuedFractionTest, Simple) {
    const auto cf = math::to_continued_fraction(mpz_class(7), mpz_class(5));
    ASSERT_EQ(cf.size(), 3);
    EXPECT_EQ(cf[0], mpz_class(1));
    EXPECT_EQ(cf[1], mpz_class(2));
    EXPECT_EQ(cf[2], mpz_class(2));
}

TEST(ToContinuedFractionTest, IntegerValue) {
    const auto cf = math::to_continued_fraction(mpz_class(6), mpz_class(1));
    ASSERT_EQ(cf.size(), 1);
    EXPECT_EQ(cf[0], mpz_class(6));
}

TEST(ToContinuedFractionTest, OneOverN) {
    const auto cf = math::to_continued_fraction(mpz_class(1), mpz_class(7));
    ASSERT_EQ(cf.size(), 2);
    EXPECT_EQ(cf[0], mpz_class(0));
    EXPECT_EQ(cf[1], mpz_class(7));
}

TEST(ToContinuedFractionTest, InvalidDenominatorZero) {
    EXPECT_THROW(math::to_continued_fraction(mpz_class(5), mpz_class(0)),
                 std::invalid_argument);
}

TEST(ToContinuedFractionTest, InvalidDenominatorNegative) {
    EXPECT_THROW(math::to_continued_fraction(mpz_class(5), mpz_class(-3)),
                 std::invalid_argument);
}

TEST(FromContinuedFractionTest, Simple) {
    const std::vector<mpz_class> cf = {1, 2, 2};
    const auto                   f = math::from_continued_fraction(cf);
    EXPECT_EQ(f.num, mpz_class(7));
    EXPECT_EQ(f.den, mpz_class(5));
}

TEST(FromContinuedFractionTest, SingleElement) {
    const std::vector<mpz_class> cf = {6};
    const auto                   f = math::from_continued_fraction(cf);
    EXPECT_EQ(f.num, mpz_class(6));
    EXPECT_EQ(f.den, mpz_class(1));
}

TEST(FromContinuedFractionTest, Empty) {
    EXPECT_THROW(math::from_continued_fraction({}), std::invalid_argument);
}

TEST(FromContinuedFractionTest, Roundtrip) {
    const mpz_class a(355), b(113);
    const auto      f =
        math::from_continued_fraction(math::to_continued_fraction(a, b));
    EXPECT_EQ(f.num, a);
    EXPECT_EQ(f.den, b);
}

TEST(ConvergentsFromCFTest, LastIsOriginal) {
    const mpz_class a(17), b(12);
    const auto      convs =
        math::convergents_from_cf(math::to_continued_fraction(a, b));
    ASSERT_FALSE(convs.empty());
    EXPECT_EQ(convs.back().num, a);
    EXPECT_EQ(convs.back().den, b);
}

TEST(ConvergentsFromCFTest, Empty) {
    EXPECT_THROW(math::convergents_from_cf({}), std::invalid_argument);
}

TEST(ConvergentsFromCFTest, KnownValues) {
    const std::vector<mpz_class> cf = {1, 2, 2};
    const auto                   convs = math::convergents_from_cf(cf);
    ASSERT_EQ(convs.size(), 3);
    EXPECT_EQ(convs[0].num, mpz_class(1));
    EXPECT_EQ(convs[0].den, mpz_class(1));
    EXPECT_EQ(convs[1].num, mpz_class(3));
    EXPECT_EQ(convs[1].den, mpz_class(2));
    EXPECT_EQ(convs[2].num, mpz_class(7));
    EXPECT_EQ(convs[2].den, mpz_class(5));
}

TEST(ConvergentsTest, MatchesConvergentsFromCF) {
    const mpz_class a(17), b(12);
    const auto      convs1 = math::convergents(a, b);
    const auto      convs2 =
        math::convergents_from_cf(math::to_continued_fraction(a, b));
    ASSERT_EQ(convs1.size(), convs2.size());
    for (size_t i = 0; i < convs1.size(); ++i) {
        EXPECT_EQ(convs1[i].num, convs2[i].num);
        EXPECT_EQ(convs1[i].den, convs2[i].den);
    }
}

TEST(CalkinWilfPathTest, Roundtrip_3_5) {
    const mpz_class a(3), b(5);
    const auto      path = math::calkin_wilf_path(a, b);
    const auto      f = math::calkin_wilf_from_path(path);
    EXPECT_EQ(f.num, a);
    EXPECT_EQ(f.den, b);
}

TEST(CalkinWilfPathTest, Roundtrip_1_1) {
    const mpz_class a(1), b(1);
    const auto      path = math::calkin_wilf_path(a, b);
    EXPECT_TRUE(path.empty());
    const auto f = math::calkin_wilf_from_path(path);
    EXPECT_EQ(f.num, a);
    EXPECT_EQ(f.den, b);
}

TEST(CalkinWilfPathTest, Roundtrip_13_8) {
    const mpz_class a(13), b(8);
    const auto      path = math::calkin_wilf_path(a, b);
    const auto      f = math::calkin_wilf_from_path(path);
    EXPECT_EQ(f.num, a);
    EXPECT_EQ(f.den, b);
}

TEST(CalkinWilfPathTest, InvalidNotCoprime) {
    EXPECT_THROW(math::calkin_wilf_path(mpz_class(4), mpz_class(6)),
                 std::invalid_argument);
}

TEST(CalkinWilfPathTest, InvalidNonPositive) {
    EXPECT_THROW(math::calkin_wilf_path(mpz_class(0), mpz_class(5)),
                 std::invalid_argument);
    EXPECT_THROW(math::calkin_wilf_path(mpz_class(3), mpz_class(-1)),
                 std::invalid_argument);
}

TEST(SternBrocotPathTest, Roundtrip_3_5) {
    const mpz_class a(3), b(5);
    const auto      path = math::stern_brocot_path(a, b);
    const auto      f = math::stern_brocot_from_path(path);
    EXPECT_EQ(f.num, a);
    EXPECT_EQ(f.den, b);
}

TEST(SternBrocotPathTest, Roundtrip_1_1) {
    const mpz_class a(1), b(1);
    const auto      path = math::stern_brocot_path(a, b);
    EXPECT_TRUE(path.empty());
    const auto f = math::stern_brocot_from_path(path);
    EXPECT_EQ(f.num, a);
    EXPECT_EQ(f.den, b);
}

TEST(SternBrocotPathTest, Roundtrip_7_11) {
    const mpz_class a(7), b(11);
    const auto      path = math::stern_brocot_path(a, b);
    const auto      f = math::stern_brocot_from_path(path);
    EXPECT_EQ(f.num, a);
    EXPECT_EQ(f.den, b);
}

TEST(SternBrocotPathTest, InvalidNotCoprime) {
    EXPECT_THROW(math::stern_brocot_path(mpz_class(4), mpz_class(6)),
                 std::invalid_argument);
}

TEST(SternBrocotPathTest, InvalidNonPositive) {
    EXPECT_THROW(math::stern_brocot_path(mpz_class(0), mpz_class(5)),
                 std::invalid_argument);
    EXPECT_THROW(math::stern_brocot_path(mpz_class(3), mpz_class(-1)),
                 std::invalid_argument);
}

TEST(ConvergentsBySternBrocotPathTest, LastIsOriginal) {
    const mpz_class a(3), b(5);
    const auto      path = math::stern_brocot_path(a, b);
    const auto      convs = math::convergents_by_stern_brocot_path(path);
    ASSERT_FALSE(convs.empty());
    EXPECT_EQ(convs.back().num, a);
    EXPECT_EQ(convs.back().den, b);
}

TEST(ConvergentsBySternBrocotPathTest, Root_1_1) {
    const auto path = math::stern_brocot_path(mpz_class(1), mpz_class(1));
    const auto convs = math::convergents_by_stern_brocot_path(path);
    ASSERT_EQ(convs.size(), 1);
    EXPECT_EQ(convs.back().num, mpz_class(1));
    EXPECT_EQ(convs.back().den, mpz_class(1));
}

TEST(ConvergentsBySternBrocotPathTest, AllPositive) {
    const mpz_class a(5), b(8);
    const auto      path = math::stern_brocot_path(a, b);
    const auto      convs = math::convergents_by_stern_brocot_path(path);
    for (const auto &f : convs) {
        EXPECT_GT(f.num, mpz_class(0));
        EXPECT_GT(f.den, mpz_class(0));
    }
}
