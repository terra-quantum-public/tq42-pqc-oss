#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <vector>

#include <gtest/gtest.h>

#include <pqc/common.h>
#include <pqc/ml-kem.h>
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

class ML_KEM_KAT_test_data
{
public:
    ML_KEM_KAT_test_data(uint32_t mode, const std::string & path, size_t n) : cipher(mode), rsp_path(path), num_tests(n)
    {
    }
    uint32_t cipher;
    std::string rsp_path;
    size_t num_tests;
};

void PrintTo(const ML_KEM_KAT_test_data & data, std::ostream * os) { *os << data.rsp_path; }

class ML_KEM_KEYGEN_TEST : public testing::TestWithParam<ML_KEM_KAT_test_data>
{
};

TEST_P(ML_KEM_KEYGEN_TEST, KAT)
{
    ML_KEM_KAT_test_data params = GetParam();
    const uint32_t cipher = params.cipher;

    static const std::filesystem::path current(__FILE__);
    static const auto base_path = current.parent_path() / "mlkem";
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
        Hex::to_uint_8_t(expected, "z = ", entropy.data() + 32, 32);

        std::getline(responses, expected);
        Hex::to_uint_8_t(expected, "d = ", entropy.data(), 32);

        std::getline(responses, expected);
        Hex::to_uint_8_t(expected, "ek = ", kat_pk.data(), kat_pk.size());

        std::getline(responses, expected);
        Hex::to_uint_8_t(expected, "dk = ", kat_sk.data(), kat_sk.size());

        CIPHER_HANDLE alice = PQC_context_init_asymmetric(cipher, nullptr, 0, nullptr, 0);
        EXPECT_NE(alice, PQC_BAD_CIPHER) << "context initialization should pass";

        PQC_context_random_set_external(alice, EntropyEmulator::get_entropy);

        EXPECT_EQ(PQC_context_keypair_generate(alice), PQC_OK) << "key generation should succeed";

        EXPECT_EQ(PQC_context_get_keypair(alice, pk.data(), pk.size(), sk.data(), sk.size()), PQC_OK)
            << "PQC_context_get_public_key should return OK";

        PQC_context_close(alice);

        EXPECT_TRUE(pk == kat_pk) << "public key equal";
        EXPECT_TRUE(sk == kat_sk) << "secure key equal";
    }
}

INSTANTIATE_TEST_SUITE_P(
    ML_KEM_KEYGEN_KAT_TESTS, ML_KEM_KEYGEN_TEST,
    testing::Values(
        ML_KEM_KAT_test_data(PQC_CIPHER_ML_KEM_512, "ml-kem-512-keygen.rsp", 25),
        ML_KEM_KAT_test_data(PQC_CIPHER_ML_KEM_768, "ml-kem-768-keygen.rsp", 25),
        ML_KEM_KAT_test_data(PQC_CIPHER_ML_KEM_1024, "ml-kem-1024-keygen.rsp", 25)
    )
);

class ML_KEM_ENCAP_TEST : public testing::TestWithParam<ML_KEM_KAT_test_data>
{
};

TEST_P(ML_KEM_ENCAP_TEST, KAT)
{
    ML_KEM_KAT_test_data params = GetParam();
    const uint32_t cipher = params.cipher;

    static const std::filesystem::path current(__FILE__);
    static const auto base_path = current.parent_path() / "mlkem";
    const auto responses_path = base_path / params.rsp_path;

    const size_t pk_len = PQC_cipher_get_length(cipher, PQC_LENGTH_PUBLIC);
    const size_t ss_len = PQC_cipher_get_length(cipher, PQC_LENGTH_SHARED);
    const size_t ct_len = PQC_cipher_get_length(cipher, PQC_LENGTH_MESSAGE);
    std::vector<uint8_t> pk(pk_len);
    std::vector<uint8_t> ss(ss_len);
    std::vector<uint8_t> kat_ss(ss_len);
    std::vector<uint8_t> ct(ct_len);
    std::vector<uint8_t> kat_ct(ct_len);

    static std::vector<uint8_t> entropy(32);
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
        Hex::to_uint_8_t(expected, "ek = ", pk.data(), pk.size());

        std::getline(responses, expected);
        Hex::to_uint_8_t(expected, "c = ", kat_ct.data(), kat_ct.size());

        std::getline(responses, expected);
        Hex::to_uint_8_t(expected, "k = ", kat_ss.data(), kat_ss.size());

        std::getline(responses, expected);
        Hex::to_uint_8_t(expected, "m = ", entropy.data(), 32);

        CIPHER_HANDLE bob = PQC_context_init_asymmetric(cipher, pk.data(), pk.size(), nullptr, 0);
        EXPECT_NE(bob, PQC_BAD_CIPHER) << "context initialization should pass";

        PQC_context_random_set_external(bob, EntropyEmulator::get_entropy);

        EXPECT_EQ(PQC_kem_encapsulate_secret(bob, ct.data(), ct.size(), ss.data(), ss.size()), PQC_OK);

        PQC_context_close(bob);

        EXPECT_TRUE(ct == kat_ct) << "cipher text equal";
        EXPECT_TRUE(ss == kat_ss) << "shared secret equal";
    }
}

INSTANTIATE_TEST_SUITE_P(
    ML_KEM_ENCAP_KAT_TESTS, ML_KEM_ENCAP_TEST,
    testing::Values(
        ML_KEM_KAT_test_data(PQC_CIPHER_ML_KEM_512, "ml-kem-512-encap.rsp", 25),
        ML_KEM_KAT_test_data(PQC_CIPHER_ML_KEM_768, "ml-kem-768-encap.rsp", 25),
        ML_KEM_KAT_test_data(PQC_CIPHER_ML_KEM_1024, "ml-kem-1024-encap.rsp", 25)
    )
);

class ML_KEM_DECAP_TEST : public testing::TestWithParam<ML_KEM_KAT_test_data>
{
};

TEST_P(ML_KEM_DECAP_TEST, KAT)
{
    ML_KEM_KAT_test_data params = GetParam();
    const uint32_t cipher = params.cipher;

    static const std::filesystem::path current(__FILE__);
    static const auto base_path = current.parent_path() / "mlkem";
    const auto responses_path = base_path / params.rsp_path;

    const size_t sk_len = PQC_cipher_get_length(cipher, PQC_LENGTH_PRIVATE);
    const size_t ss_len = PQC_cipher_get_length(cipher, PQC_LENGTH_SHARED);
    const size_t ct_len = PQC_cipher_get_length(cipher, PQC_LENGTH_MESSAGE);
    std::vector<uint8_t> kat_sk(sk_len);
    std::vector<uint8_t> ss(ss_len);
    std::vector<uint8_t> kat_ss(ss_len);
    std::vector<uint8_t> kat_ct(ct_len);

    std::string expected;

    std::ifstream responses(responses_path);
    std::getline(responses, expected);
    std::getline(responses, expected);
    std::getline(responses, expected);
    Hex::to_uint_8_t(expected, "dk = ", kat_sk.data(), kat_sk.size());

    CIPHER_HANDLE context = PQC_context_init_asymmetric(cipher, nullptr, 0, kat_sk.data(), kat_sk.size());
    EXPECT_NE(context, PQC_BAD_CIPHER);

    for (size_t i = 0; i < params.num_tests; ++i)
    {
        std::getline(responses, expected);
        EXPECT_TRUE(expected == "");

        std::getline(responses, expected);
        EXPECT_TRUE(expected == ("count = " + std::to_string(i)));

        std::getline(responses, expected);
        Hex::to_uint_8_t(expected, "c = ", kat_ct.data(), kat_ct.size());

        std::getline(responses, expected);
        Hex::to_uint_8_t(expected, "k = ", kat_ss.data(), kat_ss.size());

        EXPECT_EQ(PQC_kem_decapsulate_secret(context, kat_ct.data(), kat_ct.size(), ss.data(), ss.size()), PQC_OK);

        EXPECT_TRUE(ss == kat_ss) << "shared secret equal";
    }
}

INSTANTIATE_TEST_SUITE_P(
    ML_KEM_DECAP_KAT_TESTS, ML_KEM_DECAP_TEST,
    testing::Values(
        ML_KEM_KAT_test_data(PQC_CIPHER_ML_KEM_512, "ml-kem-512-decap.rsp", 10),
        ML_KEM_KAT_test_data(PQC_CIPHER_ML_KEM_768, "ml-kem-768-decap.rsp", 10),
        ML_KEM_KAT_test_data(PQC_CIPHER_ML_KEM_1024, "ml-kem-1024-decap.rsp", 10)
    )
);
