#include <gtest/gtest.h>

#include <array>
#include <pqc/random.h>

size_t get_randomness(uint8_t * buf, size_t size)
{
    for (size_t i = 0; i < size; ++i)
    {
        buf[i] = static_cast<uint8_t>(i);
    }
    return PQC_OK;
}

template <size_t N> void test_ext_rng()
{
    std::array<uint8_t, N> buffer;

    CIPHER_HANDLE context = PQC_context_init_randomsource();
    EXPECT_NE(context, PQC_BAD_CONTEXT) << "Context intialization should pass";

    EXPECT_EQ(PQC_context_random_set_external(context, get_randomness), PQC_OK)
        << "should be possible to set external generator";

    EXPECT_EQ(PQC_context_random_get_bytes(context, buffer.data(), N), PQC_OK)
        << "should be possible to read random bytes";

    for (size_t i = 0; i < N; ++i)
        EXPECT_EQ(buffer[i], static_cast<uint8_t>(i));

    PQC_context_close(context);
}

TEST(EXTERNAL_RANDOM_GENERATOR, CHECK_CORRECT_WITH_DIFF_SIZES)
{
    test_ext_rng<1>();
    test_ext_rng<8>();
    test_ext_rng<16>();
    test_ext_rng<1000>();
}

TEST(RANDOM_GENERATOR, FAIL_IF_NO_CONTEXT)
{
    const int N = 19;

    std::array<uint8_t, N> buffer;

    CIPHER_HANDLE context = PQC_context_init_randomsource();
    EXPECT_NE(context, PQC_BAD_CONTEXT) << "Context intialization should pass";

    EXPECT_EQ(PQC_context_random_set_external(context, get_randomness), PQC_OK)
        << "should be possible to set external generator";

    PQC_context_close(context);

    EXPECT_EQ(PQC_context_random_get_bytes(context, buffer.data(), N), PQC_BAD_CONTEXT)
        << "should fail, as context is closed";
}