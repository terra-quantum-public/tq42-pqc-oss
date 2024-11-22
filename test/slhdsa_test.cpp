#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <vector>

#include <gtest/gtest.h>

#include <pqc/random.h>
#include <pqc/sha3.h>
#include <pqc/slh-dsa.h>

struct Hex
{
    static std::string to_string(uint8_t * data, size_t size)
    {
        std::ostringstream s;
        s << std::hex << std::uppercase;
        for (size_t i = 0; i < size; ++i)
        {
            s << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(data[i]);
        }
        return s.str();
    }

    static void to_uint_8_t(std::string line, const std::string & label, uint8_t * data, size_t size)
    {
        auto values = line.substr(label.length());
        std::istringstream s(values);
        std::string ss;
        for (size_t i = 0; i < size; ++i)
        {
            s >> std::hex >> std::uppercase >> std::setw(2) >> ss;
            data[i] = static_cast<uint8_t>(std::stoi(ss, nullptr, 16));
        }
    }

    static unsigned long long to_ull(std::string line, const std::string & label)
    {
        auto values = line.substr(label.length());
        return std::stoull(values);
    }
};

class SLH_DSA_KAT_test_data
{
public:
    SLH_DSA_KAT_test_data(uint32_t mode, const std::string & path, size_t n)
        : cipher(mode), rsp_path(path), num_tests(n)
    {
    }
    uint32_t cipher;
    std::string rsp_path;
    size_t num_tests;
};

void PrintTo(const SLH_DSA_KAT_test_data & data, std::ostream * os) { *os << data.rsp_path; }

class SLH_DSA_KEYGEN_TEST : public testing::TestWithParam<SLH_DSA_KAT_test_data>
{
};

TEST_P(SLH_DSA_KEYGEN_TEST, KAT)
{
    SLH_DSA_KAT_test_data params = GetParam();
    const uint32_t cipher = params.cipher;

    static const std::filesystem::path current(__FILE__);
    static const auto base_path = current.parent_path() / "slhdsa";
    const auto responses_path = base_path / params.rsp_path;

    const size_t pk_len = PQC_cipher_get_length(cipher, PQC_LENGTH_PUBLIC);
    const size_t sk_len = PQC_cipher_get_length(cipher, PQC_LENGTH_PRIVATE);
    std::vector<uint8_t> pk(pk_len);
    std::vector<uint8_t> sk(sk_len);
    std::vector<uint8_t> kat_pk(pk_len);
    std::vector<uint8_t> kat_sk(sk_len);

    const size_t n = pk_len / 2;
    static std::vector<uint8_t> entropy;
    static size_t offset = 0;

    offset = 0;
    entropy.resize(n * 3, 0);

    struct EntropyEmulator
    {
        static size_t get_entropy(uint8_t * buf, size_t size)
        {
            std::copy_n(entropy.begin() + offset, size, buf);
            offset += size;
            return PQC_OK;
        }
    };

    std::string expected;

    std::ifstream responses(responses_path);
    std::getline(responses, expected);

    for (size_t i = 0; i < params.num_tests; ++i)
    {
        offset = 0;

        std::getline(responses, expected);
        EXPECT_TRUE(expected == "");

        std::getline(responses, expected);
        EXPECT_TRUE(expected == ("count = " + std::to_string(i)));

        std::getline(responses, expected);
        Hex::to_uint_8_t(expected, "skSeed = ", entropy.data(), n);

        std::getline(responses, expected);
        Hex::to_uint_8_t(expected, "skPrf = ", entropy.data() + n, n);

        std::getline(responses, expected);
        Hex::to_uint_8_t(expected, "pkSeed = ", entropy.data() + 2 * n, n);

        std::getline(responses, expected);
        Hex::to_uint_8_t(expected, "sk = ", kat_sk.data(), kat_sk.size());

        std::getline(responses, expected);
        Hex::to_uint_8_t(expected, "pk = ", kat_pk.data(), kat_pk.size());

        CIPHER_HANDLE alice = PQC_context_init_asymmetric(cipher, nullptr, 0, kat_sk.data(), kat_sk.size());
        EXPECT_NE(alice, PQC_BAD_CIPHER) << "context initialization should pass";
        PQC_context_random_set_external(alice, EntropyEmulator::get_entropy);

        EXPECT_EQ(PQC_context_keypair_generate(alice), PQC_OK) << "keys made";

        EXPECT_EQ(PQC_context_get_keypair(alice, pk.data(), pk.size(), sk.data(), sk.size()), PQC_OK) << "keys get";
        EXPECT_TRUE(pk == kat_pk) << "public key equal";
        EXPECT_TRUE(sk == kat_sk) << "secure key equal";

        PQC_context_close(alice);
    }
}

INSTANTIATE_TEST_SUITE_P(
    SLH_DSA_KEYGEN_KAT_TESTS, SLH_DSA_KEYGEN_TEST,
    testing::Values(
        SLH_DSA_KAT_test_data(PQC_CIPHER_SLH_DSA_SHAKE_192S, "shake-192s-keygen.rsp", 10),
        SLH_DSA_KAT_test_data(PQC_CIPHER_SLH_DSA_SHAKE_256F, "shake-256f-keygen.rsp", 10),
        SLH_DSA_KAT_test_data(PQC_CIPHER_SLH_DSA_SHAKE_256F, "shake-256f-keygen-atsec.rsp", 10)
    )
);

class SLH_DSA_SIGGEN_TEST : public testing::TestWithParam<SLH_DSA_KAT_test_data>
{
};

TEST_P(SLH_DSA_SIGGEN_TEST, KAT)
{
    SLH_DSA_KAT_test_data params = GetParam();
    const uint32_t cipher = params.cipher;

    static const std::filesystem::path current(__FILE__);
    static const auto base_path = current.parent_path() / "slhdsa";
    const auto responses_path = base_path / params.rsp_path;

    const size_t sk_len = PQC_cipher_get_length(cipher, PQC_LENGTH_PRIVATE);
    const size_t sig_len = PQC_cipher_get_length(cipher, PQC_LENGTH_SIGNATURE);
    std::vector<uint8_t> sk(sk_len);
    std::vector<uint8_t> sig(sig_len);
    std::vector<uint8_t> kat_sig(sig_len);

    const size_t n = sk_len / 4;
    static std::vector<uint8_t> entropy;
    static size_t offset = 0;
    offset = 0;
    entropy.resize(n * 3, 0);
    struct EntropyEmulator
    {
        static size_t get_entropy(uint8_t * buf, size_t size)
        {
            std::copy_n(entropy.begin() + offset, size, buf);
            offset += size;
            return PQC_OK;
        }
    };

    std::string expected;

    std::ifstream responses(responses_path);
    std::getline(responses, expected);

    for (size_t i = 0; i < params.num_tests; ++i)
    {
        offset = 0;

        std::getline(responses, expected);
        EXPECT_TRUE(expected == "");

        std::getline(responses, expected);
        EXPECT_TRUE(expected == ("count = " + std::to_string(i)));

        std::getline(responses, expected);
        Hex::to_uint_8_t(expected, "sk = ", sk.data(), sk.size());

        std::getline(responses, expected);
        Hex::to_uint_8_t(expected, "seed = ", entropy.data(), n);

        std::getline(responses, expected);
        unsigned long long smlen = Hex::to_ull(expected, "msglen = ");

        std::getline(responses, expected);
        std::vector<uint8_t> msg(smlen / 8);
        Hex::to_uint_8_t(expected, "msg = ", msg.data(), msg.size());

        std::getline(responses, expected);
        Hex::to_uint_8_t(expected, "signature = ", kat_sig.data(), kat_sig.size());

        CIPHER_HANDLE alice = PQC_context_init_asymmetric(cipher, nullptr, 0, sk.data(), sk.size());
        EXPECT_NE(alice, PQC_BAD_CIPHER) << "context initialization should pass";
        PQC_context_random_set_external(alice, EntropyEmulator::get_entropy);

        EXPECT_EQ(PQC_signature_create(alice, msg.data(), msg.size(), sig.data(), sig.size()), PQC_OK)
            << "signing should succeed";

        EXPECT_TRUE(sig == kat_sig) << "signature equal";

        PQC_context_close(alice);
    }
}

#ifndef NDEBUG
INSTANTIATE_TEST_SUITE_P(
    SLH_DSA_SIGGEN_KAT_TESTS, SLH_DSA_SIGGEN_TEST,
    testing::Values(
        SLH_DSA_KAT_test_data(PQC_CIPHER_SLH_DSA_SHAKE_128F, "shake-128f-siggen.rsp", 2),
        SLH_DSA_KAT_test_data(PQC_CIPHER_SLH_DSA_SHAKE_192S, "shake-192s-siggen.rsp", 1),
        SLH_DSA_KAT_test_data(PQC_CIPHER_SLH_DSA_SHAKE_256F, "shake-256f-siggen.rsp", 2),
        SLH_DSA_KAT_test_data(PQC_CIPHER_SLH_DSA_SHAKE_256F, "shake-256f-siggen-atsec.rsp", 2)
    )
);
#else
INSTANTIATE_TEST_SUITE_P(
    SLH_DSA_SIGGEN_KAT_TESTS, SLH_DSA_SIGGEN_TEST,
    testing::Values(
        SLH_DSA_KAT_test_data(PQC_CIPHER_SLH_DSA_SHAKE_128F, "shake-128f-siggen.rsp", 10),
        SLH_DSA_KAT_test_data(PQC_CIPHER_SLH_DSA_SHAKE_192S, "shake-192s-siggen.rsp", 7),
        SLH_DSA_KAT_test_data(PQC_CIPHER_SLH_DSA_SHAKE_256F, "shake-256f-siggen.rsp", 10),
        SLH_DSA_KAT_test_data(PQC_CIPHER_SLH_DSA_SHAKE_256F, "shake-256f-siggen-atsec.rsp", 10)
    )
);
#endif

class SLH_DSA_SIGVER_TEST : public testing::TestWithParam<SLH_DSA_KAT_test_data>
{
};

TEST_P(SLH_DSA_SIGVER_TEST, KAT)
{
    SLH_DSA_KAT_test_data params = GetParam();
    const uint32_t cipher = params.cipher;

    static const std::filesystem::path current(__FILE__);
    static const auto base_path = current.parent_path() / "slhdsa";
    const auto responses_path = base_path / params.rsp_path;

    const size_t pk_len = PQC_cipher_get_length(cipher, PQC_LENGTH_PUBLIC);
    std::vector<uint8_t> pk(pk_len);

    std::string expected;
    std::ifstream responses(responses_path);

    std::getline(responses, expected);

    for (size_t i = 0; i < params.num_tests; ++i)
    {
        std::getline(responses, expected);
        EXPECT_TRUE(expected == "");

        std::getline(responses, expected);
        EXPECT_TRUE(expected == ("count = " + std::to_string(i)));

        std::getline(responses, expected);
        unsigned long long passed = Hex::to_ull(expected, "testPassed = ");

        std::getline(responses, expected);
        Hex::to_uint_8_t(expected, "pk = ", pk.data(), pk.size());

        std::getline(responses, expected);
        unsigned long long mlen = Hex::to_ull(expected, "msglen = ");

        std::getline(responses, expected);
        std::vector<uint8_t> msg(mlen / 8);
        Hex::to_uint_8_t(expected, "message = ", msg.data(), msg.size());

        std::getline(responses, expected);
        std::vector<uint8_t> sig((expected.substr(std::string("signature = ").length()).length()) / 2);
        Hex::to_uint_8_t(expected, "signature = ", sig.data(), sig.size());

        CIPHER_HANDLE context = PQC_context_init_asymmetric(cipher, pk.data(), pk.size(), nullptr, 0);
        EXPECT_NE(context, PQC_BAD_CIPHER);

        if (passed)
        {
            EXPECT_EQ(PQC_signature_verify(context, msg.data(), msg.size(), sig.data(), sig.size()), PQC_OK)
                << "signature should match";
        }
        else
        {
            EXPECT_NE(PQC_signature_verify(context, msg.data(), msg.size(), sig.data(), sig.size()), PQC_OK)
                << "signature shouldn't match";
        }
        PQC_context_close(context);
    }
}

INSTANTIATE_TEST_SUITE_P(
    SLH_DSA_SIGVER_KAT_TESTS, SLH_DSA_SIGVER_TEST,
    testing::Values(
        SLH_DSA_KAT_test_data(PQC_CIPHER_SLH_DSA_SHAKE_128F, "shake-128f-sigver.rsp", 9),
        SLH_DSA_KAT_test_data(PQC_CIPHER_SLH_DSA_SHAKE_192S, "shake-192s-sigver.rsp", 9),
        SLH_DSA_KAT_test_data(PQC_CIPHER_SLH_DSA_SHAKE_256F, "shake-256f-sigver.rsp", 7),
        SLH_DSA_KAT_test_data(PQC_CIPHER_SLH_DSA_SHAKE_256F, "shake-256f-sigver-atsec.rsp", 9)
    )
);
