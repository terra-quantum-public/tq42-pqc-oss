#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>

#include <gtest/gtest.h>

#include <pqc/common.h>
#include <pqc/kyber.h>
#include <pqc/random.h>

class KYBER_KAT_test_data
{
public:
    KYBER_KAT_test_data(uint32_t mode, const std::string & path, size_t n) : cipher(mode), rsp_path(path), num_tests(n)
    {
    }
    uint32_t cipher;
    std::string rsp_path;
    size_t num_tests;
};

void PrintTo(const KYBER_KAT_test_data & data, std::ostream * os) { *os << data.rsp_path; }

class KYBER_KAT_TEST : public testing::TestWithParam<KYBER_KAT_test_data>
{
};

TEST_P(KYBER_KAT_TEST, Round3)
{
    KYBER_KAT_test_data params = GetParam();
    const uint32_t cipher = params.cipher;

    static const std::filesystem::path current(__FILE__);
    static const auto base_path = current.parent_path() / "mlkem";
    static const auto responses_path = base_path / params.rsp_path;
    static const auto entropy_path = base_path / "kyber1024-KAT.ent";

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

    struct EntropyReader
    {
        static size_t get_entropy(uint8_t * buf, size_t size)
        {
            static std::ifstream f(entropy_path, std::ios_base::in | std::ios_base::binary);
            f.exceptions(std::ios_base::badbit | std::ios_base::eofbit);
            f.read(reinterpret_cast<char *>(buf), size);
            return PQC_OK;
        }
    };

    std::ifstream responses(responses_path);
    std::string expected;

    std::getline(responses, expected);

    const size_t pk_len = PQC_cipher_get_length(cipher, PQC_LENGTH_PUBLIC);
    const size_t sk_len = PQC_cipher_get_length(cipher, PQC_LENGTH_PRIVATE);
    const size_t ss_len = PQC_cipher_get_length(cipher, PQC_LENGTH_SHARED);
    const size_t msg_len = PQC_cipher_get_length(cipher, PQC_LENGTH_MESSAGE);
    std::vector<uint8_t> pk(pk_len);
    std::vector<uint8_t> kat_pk(pk_len);
    std::vector<uint8_t> sk(sk_len);
    std::vector<uint8_t> kat_sk(sk_len);
    std::vector<uint8_t> ss(ss_len);
    std::vector<uint8_t> kat_ss(ss_len);
    std::vector<uint8_t> ct(msg_len);
    std::vector<uint8_t> kat_ct(msg_len);

    for (size_t i = 0; i < params.num_tests; ++i)
    {
        std::getline(responses, expected);
        EXPECT_TRUE(expected == "");

        std::getline(responses, expected);
        EXPECT_TRUE(expected == ("count = " + std::to_string(i)));

        std::getline(responses, expected); // seed line

        std::getline(responses, expected);
        Hex::to_uint_8_t(expected, "pk = ", kat_pk.data(), kat_pk.size());

        std::getline(responses, expected);
        Hex::to_uint_8_t(expected, "sk = ", kat_sk.data(), kat_sk.size());

        std::getline(responses, expected);
        Hex::to_uint_8_t(expected, "ct = ", kat_ct.data(), kat_ct.size());

        std::getline(responses, expected);
        Hex::to_uint_8_t(expected, "ss = ", kat_ss.data(), kat_ss.size());

        CIPHER_HANDLE alice = PQC_context_init_asymmetric(cipher, nullptr, 0, nullptr, 0);
        EXPECT_NE(alice, PQC_BAD_CIPHER) << "context initialization should pass";

        PQC_context_random_set_external(alice, EntropyReader::get_entropy);

        EXPECT_EQ(PQC_context_keypair_generate(alice), PQC_OK) << "keys made";

        EXPECT_EQ(PQC_context_get_keypair(alice, pk.data(), pk.size(), sk.data(), sk.size()), PQC_OK)
            << "keys extracted";

        EXPECT_TRUE(pk == kat_pk) << "public key equal";
        EXPECT_TRUE(sk == kat_sk) << "secure key equal";


        CIPHER_HANDLE bob = PQC_context_init_asymmetric(cipher, pk.data(), pk.size(), nullptr, 0);
        EXPECT_NE(bob, PQC_BAD_CIPHER);

        PQC_context_random_set_external(bob, EntropyReader::get_entropy);

        EXPECT_EQ(PQC_kem_encapsulate_secret(bob, ct.data(), ct.size(), ss.data(), ss.size()), PQC_OK);
        EXPECT_TRUE(ct == kat_ct) << "cipher text equal";
        EXPECT_TRUE(ss == kat_ss) << "shared secret equal";


        EXPECT_EQ(PQC_kem_decapsulate_secret(alice, ct.data(), ct.size(), ss.data(), ss.size()), PQC_OK);
        EXPECT_TRUE(ss == kat_ss) << "decapsulate correct";

        PQC_context_close(alice);
        PQC_context_close(bob);
    }
}

INSTANTIATE_TEST_SUITE_P(
    KYBER_KAT_TESTS, KYBER_KAT_TEST,
    testing::Values(
        KYBER_KAT_test_data(PQC_CIPHER_KYBER_512, "kyber512-KAT.rsp", 100),
        KYBER_KAT_test_data(PQC_CIPHER_KYBER_768, "kyber768-KAT.rsp", 100),
        KYBER_KAT_test_data(PQC_CIPHER_KYBER_1024, "kyber1024-KAT.rsp", 100)
    )
);
