#include <gtest/gtest.h>

#include <array>
#include <pqc/random.h>

void get_randomness(uint8_t * buf, size_t size)
{
    for (size_t i = 0; i < size; ++i)
    {
        buf[i] = static_cast<uint8_t>(i);
    }
}

template <size_t N> void test_ext_rng()
{
    std::array<uint8_t, N> buffer;
    PQC_random_bytes(buffer.data(), N);
    for (size_t i = 0; i < N; ++i)
        EXPECT_EQ(buffer[i], static_cast<uint8_t>(i));
}

TEST(EXTERNAL_RANDOM_GENERATOR, CHECK_CORRECT_WITH_DIFF_SIZES)
{
    PQC_random_from_external(get_randomness);
    test_ext_rng<1>();
    test_ext_rng<8>();
    test_ext_rng<16>();
    test_ext_rng<1000>();
}
