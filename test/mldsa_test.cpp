#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <vector>

#include <gtest/gtest.h>

#include <mldsa/mldsa_internal.h>
#include <mldsa/params.h>
#include <pqc/ml-dsa.h>
#include <pqc/random.h>

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

class ML_DSA_KAT_test_data
{
public:
    ML_DSA_KAT_test_data(uint32_t mode, const std::string & path, size_t n) : cipher(mode), rsp_path(path), num_tests(n)
    {
    }
    uint32_t cipher;
    std::string rsp_path;
    size_t num_tests;
};

void PrintTo(const ML_DSA_KAT_test_data & data, std::ostream * os) { *os << data.rsp_path; }

class ML_DSA_KEYGEN_TEST : public testing::TestWithParam<ML_DSA_KAT_test_data>
{
};

TEST_P(ML_DSA_KEYGEN_TEST, KAT)
{
    ML_DSA_KAT_test_data params = GetParam();
    const uint32_t cipher = params.cipher;

    static const std::filesystem::path current(__FILE__);
    static const auto base_path = current.parent_path() / "mldsa";
    const auto responses_path = base_path / params.rsp_path;

    const size_t pk_len = PQC_cipher_get_length(cipher, PQC_LENGTH_PUBLIC);
    const size_t sk_len = PQC_cipher_get_length(cipher, PQC_LENGTH_PRIVATE);
    std::vector<uint8_t> pk(pk_len);
    std::vector<uint8_t> sk(sk_len);
    std::vector<uint8_t> kat_pk(pk_len);
    std::vector<uint8_t> kat_sk(sk_len);

    static std::vector<uint8_t> entropy(64);
    static size_t offset = 0;
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
        Hex::to_uint_8_t(expected, "seed = ", entropy.data(), 32);

        std::getline(responses, expected);
        Hex::to_uint_8_t(expected, "pk = ", kat_pk.data(), kat_pk.size());

        std::getline(responses, expected);
        Hex::to_uint_8_t(expected, "sk = ", kat_sk.data(), kat_sk.size());

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
    ML_DSA_KEYGEN_KAT_TESTS, ML_DSA_KEYGEN_TEST,
    testing::Values(
        ML_DSA_KAT_test_data(PQC_CIPHER_ML_DSA_44, "ml-dsa-44-keygen.rsp", 25),
        ML_DSA_KAT_test_data(PQC_CIPHER_ML_DSA_65, "ml-dsa-65-keygen.rsp", 25),
        ML_DSA_KAT_test_data(PQC_CIPHER_ML_DSA_87, "ml-dsa-87-keygen.rsp", 25),
        ML_DSA_KAT_test_data(PQC_CIPHER_ML_DSA_87, "ml-dsa-87-keygen-2.rsp", 25)
    )
);

class ML_DSA_SIGGEN_TEST : public testing::TestWithParam<ML_DSA_KAT_test_data>
{
};

TEST_P(ML_DSA_SIGGEN_TEST, KAT)
{
    ML_DSA_KAT_test_data params = GetParam();
    const uint32_t cipher = params.cipher;

    static const std::filesystem::path current(__FILE__);
    static const auto base_path = current.parent_path() / "mldsa";
    const auto responses_path = base_path / params.rsp_path;

    const size_t sk_len = PQC_cipher_get_length(cipher, PQC_LENGTH_PRIVATE);
    const size_t sig_len = PQC_cipher_get_length(cipher, PQC_LENGTH_SIGNATURE);
    std::vector<uint8_t> sk(sk_len);
    std::vector<uint8_t> sig(sig_len);
    std::vector<uint8_t> kat_sig(sig_len);

    static std::vector<uint8_t> entropy(64);

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
        Hex::to_uint_8_t(expected, "sk = ", sk.data(), sk.size());

        std::getline(responses, expected);
        std::vector<uint8_t> msg((expected.substr(std::string("message = ").length()).length()) / 2);
        Hex::to_uint_8_t(expected, "message = ", msg.data(), msg.size());

        std::getline(responses, expected);
        Hex::to_uint_8_t(expected, "rnd = ", entropy.data(), 32);

        std::getline(responses, expected);
        Hex::to_uint_8_t(expected, "signature = ", kat_sig.data(), kat_sig.size());

        if (cipher == PQC_CIPHER_ML_DSA_44)
            mldsa::mldsa_sign_internal_44(
                ConstBufferView(msg.data(), msg.size()), ConstBufferView(sk.data(), sk.size()),
                ConstBufferView(entropy.data(), 32), BufferView(sig.data(), sig.size()), mldsa::MODE_44
            );
        else if (cipher == PQC_CIPHER_ML_DSA_65)
            mldsa::mldsa_sign_internal_65(
                ConstBufferView(msg.data(), msg.size()), ConstBufferView(sk.data(), sk.size()),
                ConstBufferView(entropy.data(), 32), BufferView(sig.data(), sig.size()), mldsa::MODE_65
            );
        else if (cipher == PQC_CIPHER_ML_DSA_87)
            mldsa::mldsa_sign_internal_87(
                ConstBufferView(msg.data(), msg.size()), ConstBufferView(sk.data(), sk.size()),
                ConstBufferView(entropy.data(), 32), BufferView(sig.data(), sig.size()), mldsa::MODE_87
            );

        EXPECT_TRUE(sig == kat_sig) << "signature equal";
    }
}

INSTANTIATE_TEST_SUITE_P(
    ML_DSA_SIGGEN_KAT_TESTS, ML_DSA_SIGGEN_TEST,
    testing::Values(
        ML_DSA_KAT_test_data(PQC_CIPHER_ML_DSA_44, "ml-dsa-44-siggen-hedged.rsp", 10),
        ML_DSA_KAT_test_data(PQC_CIPHER_ML_DSA_65, "ml-dsa-65-siggen-hedged.rsp", 10),
        ML_DSA_KAT_test_data(PQC_CIPHER_ML_DSA_87, "ml-dsa-87-siggen-hedged.rsp", 10),
        ML_DSA_KAT_test_data(PQC_CIPHER_ML_DSA_87, "ml-dsa87-siggen-hedged-2.rsp", 10)
    )
);

class ML_DSA_SIGVER_TEST : public testing::TestWithParam<ML_DSA_KAT_test_data>
{
};

TEST_P(ML_DSA_SIGVER_TEST, KAT)
{
    ML_DSA_KAT_test_data params = GetParam();
    const uint32_t cipher = params.cipher;

    static const std::filesystem::path current(__FILE__);
    static const auto base_path = current.parent_path() / "mldsa";
    const auto responses_path = base_path / params.rsp_path;

    const size_t pk_len = PQC_cipher_get_length(cipher, PQC_LENGTH_PUBLIC);
    std::vector<uint8_t> pk(pk_len);

    std::string expected;
    std::ifstream responses(responses_path);
    std::getline(responses, expected);
    std::getline(responses, expected);

    std::getline(responses, expected);
    Hex::to_uint_8_t(expected, "pk = ", pk.data(), pk.size());
    for (size_t i = 0; i < params.num_tests; ++i)
    {
        std::getline(responses, expected);
        EXPECT_TRUE(expected == "");

        std::getline(responses, expected);
        EXPECT_TRUE(expected == ("count = " + std::to_string(i)));

        std::getline(responses, expected);
        unsigned long long passed = Hex::to_ull(expected, "testPassed = ");

        std::getline(responses, expected);
        std::vector<uint8_t> msg((expected.substr(std::string("message = ").length()).length()) / 2);
        Hex::to_uint_8_t(expected, "message = ", msg.data(), msg.size());

        std::getline(responses, expected);
        std::vector<uint8_t> sig((expected.substr(std::string("signature = ").length()).length()) / 2);
        Hex::to_uint_8_t(expected, "signature = ", sig.data(), sig.size());

        bool result = false;
        if (cipher == PQC_CIPHER_ML_DSA_44)
            result = mldsa::mldsa_verify_internal_44(
                ConstBufferView(msg.data(), msg.size()), ConstBufferView(pk.data(), pk.size()),
                ConstBufferView(sig.data(), sig.size()), mldsa::MODE_44
            );
        else if (cipher == PQC_CIPHER_ML_DSA_65)
            result = mldsa::mldsa_verify_internal_65(
                ConstBufferView(msg.data(), msg.size()), ConstBufferView(pk.data(), pk.size()),
                ConstBufferView(sig.data(), sig.size()), mldsa::MODE_65
            );
        else if (cipher == PQC_CIPHER_ML_DSA_87)
            result = mldsa::mldsa_verify_internal_87(
                ConstBufferView(msg.data(), msg.size()), ConstBufferView(pk.data(), pk.size()),
                ConstBufferView(sig.data(), sig.size()), mldsa::MODE_87
            );
        EXPECT_EQ(result, passed);
    }
}

INSTANTIATE_TEST_SUITE_P(
    ML_DSA_SIGVER_KAT_TESTS, ML_DSA_SIGVER_TEST,
    testing::Values(
        ML_DSA_KAT_test_data(PQC_CIPHER_ML_DSA_44, "ml-dsa-44-sigver.rsp", 15),
        ML_DSA_KAT_test_data(PQC_CIPHER_ML_DSA_65, "ml-dsa-65-sigver.rsp", 15),
        ML_DSA_KAT_test_data(PQC_CIPHER_ML_DSA_87, "ml-dsa-87-sigver.rsp", 15),
        ML_DSA_KAT_test_data(PQC_CIPHER_ML_DSA_87, "ml-dsa87-sigver-2.rsp", 15)
    )
);
