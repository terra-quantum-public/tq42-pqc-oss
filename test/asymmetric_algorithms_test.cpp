#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <pqc/common.h>
#include <pqc/dilithium.h>
#include <pqc/falcon.h>
#include <pqc/kyber.h>
#include <pqc/mceliece.h>
#include <pqc/ml-dsa.h>
#include <pqc/ml-kem.h>
#include <pqc/random.h>
#include <pqc/sha3.h>
#include <pqc/slh-dsa.h>

class Asymmetric_test_data
{
public:
    Asymmetric_test_data(uint32_t cipher, std::string name) : _cipher(cipher), _name(name) {}

    uint32_t _cipher;
    std::string _name;
};

#define TEST_DATA(cipher) Asymmetric_test_data(cipher, #cipher)


class AsymmetricTestSuite : public testing::TestWithParam<Asymmetric_test_data>
{
public:
    uint32_t cipher() { return GetParam()._cipher; }
    size_t private_size() { return PQC_cipher_get_length(cipher(), PQC_LENGTH_PRIVATE); }
    size_t public_size() { return PQC_cipher_get_length(cipher(), PQC_LENGTH_PUBLIC); }
};

TEST_P(AsymmetricTestSuite, INIT_VALID_SIZE)
{
    std::vector<uint8_t> private_key(private_size(), 0);
    std::vector<uint8_t> public_key(public_size(), 0);

    CIPHER_HANDLE handle = PQC_context_init_asymmetric(
        cipher(), public_key.data(), public_key.size(), private_key.data(), private_key.size()
    );

    EXPECT_NE(handle, PQC_BAD_CIPHER) << "Initialization with correct sizes should pass";

    EXPECT_EQ(PQC_context_close(handle), PQC_OK);
}

TEST_P(AsymmetricTestSuite, INIT_VALID_SIZE_PUBLIC_ONLY)
{
    std::vector<uint8_t> public_key(public_size(), 0);

    CIPHER_HANDLE handle = PQC_context_init_asymmetric(cipher(), public_key.data(), public_key.size(), nullptr, 0);

    EXPECT_NE(handle, PQC_BAD_CIPHER) << "Initialization with correct sizes should pass";

    EXPECT_EQ(PQC_context_close(handle), PQC_OK);
}

TEST_P(AsymmetricTestSuite, INIT_VALID_SIZE_PRIVATE_ONLY)
{
    const size_t private_size = PQC_cipher_get_length(cipher(), PQC_LENGTH_PRIVATE);

    std::vector<uint8_t> private_key(private_size, 0);

    CIPHER_HANDLE handle = PQC_context_init_asymmetric(cipher(), nullptr, 0, private_key.data(), private_key.size());

    EXPECT_NE(handle, PQC_BAD_CIPHER) << "Initialization with correct sizes should pass";

    EXPECT_EQ(PQC_context_close(handle), PQC_OK);
}

TEST_P(AsymmetricTestSuite, INIT_FAIL_ON_INVALID_SIZE)
{
    std::vector<uint8_t> private_key(private_size(), 0);
    std::vector<uint8_t> public_key(public_size(), 0);

    EXPECT_EQ(
        PQC_context_init_asymmetric(
            cipher(), public_key.data(), public_key.size() - 1, private_key.data(), private_key.size()
        ),
        PQC_BAD_CIPHER
    ) << "Initialization with wrong public key size should fail";

    EXPECT_EQ(
        PQC_context_init_asymmetric(
            cipher(), public_key.data(), public_key.size(), private_key.data(), private_key.size() - 1
        ),
        PQC_BAD_CIPHER
    ) << "Initialization with wrong private key size should fail";

    EXPECT_EQ(
        PQC_context_init_asymmetric(
            cipher(), public_key.data(), public_key.size() - 1, private_key.data(), private_key.size() - 1
        ),
        PQC_BAD_CIPHER
    ) << "Initialization with all key sizes should fail";

    EXPECT_EQ(
        PQC_context_init_asymmetric(cipher(), public_key.data(), public_key.size() - 1, nullptr, 0), PQC_BAD_CIPHER
    ) << "Initialization with wrong public key size and without private key should fail";

    EXPECT_EQ(
        PQC_context_init_asymmetric(cipher(), nullptr, 0, private_key.data(), private_key.size() - 1), PQC_BAD_CIPHER
    ) << "Initialization with wrong private key size and without public key should fail";
}

TEST_P(AsymmetricTestSuite, GET_KEY_PAIR)
{
    std::vector<uint8_t> private_key(private_size(), 0);
    std::vector<uint8_t> public_key(public_size(), 0);

    for (size_t i = 0; i < private_key.size(); ++i)
    {
        private_key[i] = i % 256;
    }

    for (size_t i = 0; i < public_key.size(); ++i)
    {
        public_key[i] = (public_key.size() - i) % 256;
    }

    CIPHER_HANDLE handle = PQC_context_init_asymmetric(
        cipher(), public_key.data(), public_key.size(), private_key.data(), private_key.size()
    );

    EXPECT_NE(handle, PQC_BAD_CIPHER) << "Initialization should pass";

    std::vector<uint8_t> actual_private_key(private_size(), 0);
    std::vector<uint8_t> actual_public_key(public_size(), 0);

    EXPECT_EQ(
        PQC_context_get_keypair(
            handle, actual_public_key.data(), actual_public_key.size(), actual_private_key.data(),
            actual_private_key.size()
        ),
        PQC_OK
    ) << "PQC_context_get_keypair should return OK";

    EXPECT_EQ(actual_private_key, private_key);
    EXPECT_EQ(actual_public_key, public_key);

    EXPECT_EQ(PQC_context_close(handle), PQC_OK);
}

TEST_P(AsymmetricTestSuite, GET_PUBLIC_KEY)
{
    std::vector<uint8_t> private_key(private_size(), 0);
    std::vector<uint8_t> public_key(public_size(), 0);

    for (size_t i = 0; i < private_key.size(); ++i)
    {
        private_key[i] = i % 256;
    }

    for (size_t i = 0; i < public_key.size(); ++i)
    {
        public_key[i] = (public_key.size() - i) % 256;
    }

    CIPHER_HANDLE handle = PQC_context_init_asymmetric(
        cipher(), public_key.data(), public_key.size(), private_key.data(), private_key.size()
    );

    EXPECT_NE(handle, PQC_BAD_CIPHER) << "Initialization should pass";

    std::vector<uint8_t> actual_public_key(public_size(), 0);

    EXPECT_EQ(PQC_context_get_public_key(handle, actual_public_key.data(), actual_public_key.size()), PQC_OK)
        << "PQC_context_get_public_key should return OK";

    EXPECT_EQ(actual_public_key, public_key);

    EXPECT_EQ(PQC_context_close(handle), PQC_OK);
}


TEST_P(AsymmetricTestSuite, GET_PUBLIC_KEY_FAIL_ON_WRONG_SIZE)
{
    std::vector<uint8_t> private_key(private_size(), 0);
    std::vector<uint8_t> public_key(public_size(), 0);

    for (size_t i = 0; i < private_key.size(); ++i)
    {
        private_key[i] = i % 256;
    }

    for (size_t i = 0; i < public_key.size(); ++i)
    {
        public_key[i] = (public_key.size() - i) % 256;
    }

    CIPHER_HANDLE handle = PQC_context_init_asymmetric(
        cipher(), public_key.data(), public_key.size(), private_key.data(), private_key.size()
    );

    EXPECT_NE(handle, PQC_BAD_CIPHER) << "Initialization should pass";

    std::vector<uint8_t> actual_public_key(public_size(), 0);

    EXPECT_EQ(PQC_context_get_public_key(handle, actual_public_key.data(), actual_public_key.size() - 1), PQC_BAD_LEN)
        << "PQC_context_get_public_key should fail";

    EXPECT_EQ(PQC_context_close(handle), PQC_OK);
}

TEST_P(AsymmetricTestSuite, GET_PUBLIC_KEY_FAIL_ON_NOT_SET)
{
    CIPHER_HANDLE handle = PQC_context_init_asymmetric(cipher(), nullptr, 0, nullptr, 0);

    EXPECT_NE(handle, PQC_BAD_CIPHER) << "Initialization should pass";

    std::vector<uint8_t> actual_public_key(public_size(), 0);

    EXPECT_EQ(PQC_context_get_public_key(handle, actual_public_key.data(), actual_public_key.size()), PQC_KEY_NOT_SET)
        << "PQC_context_get_public_key should fail";

    EXPECT_EQ(PQC_context_close(handle), PQC_OK);
}

TEST_P(AsymmetricTestSuite, GET_KEYPAIR_FAIL_ON_NOT_SET)
{
    CIPHER_HANDLE handle = PQC_context_init_asymmetric(cipher(), nullptr, 0, nullptr, 0);

    EXPECT_NE(handle, PQC_BAD_CIPHER) << "Initialization should pass";

    std::vector<uint8_t> actual_private_key(private_size(), 0);
    std::vector<uint8_t> actual_public_key(public_size(), 0);

    EXPECT_EQ(
        PQC_context_get_keypair(
            handle, actual_public_key.data(), actual_public_key.size(), actual_private_key.data(),
            actual_private_key.size()
        ),
        PQC_KEY_NOT_SET
    ) << "PQC_context_get_keypair should fail";

    EXPECT_EQ(PQC_context_close(handle), PQC_OK);
}

static std::string TestDataToString(const testing::TestParamInfo<Asymmetric_test_data> & info)
{
    return info.param._name;
}

INSTANTIATE_TEST_SUITE_P(
    Asymmetric, AsymmetricTestSuite,
    testing::Values(
        TEST_DATA(PQC_CIPHER_DILITHIUM), TEST_DATA(PQC_CIPHER_FALCON), TEST_DATA(PQC_CIPHER_KYBER_512),
        TEST_DATA(PQC_CIPHER_KYBER_768), TEST_DATA(PQC_CIPHER_KYBER_1024), TEST_DATA(PQC_CIPHER_MCELIECE),
        TEST_DATA(PQC_CIPHER_ML_DSA_44), TEST_DATA(PQC_CIPHER_ML_DSA_65), TEST_DATA(PQC_CIPHER_ML_DSA_87),
        TEST_DATA(PQC_CIPHER_ML_KEM_512), TEST_DATA(PQC_CIPHER_ML_KEM_768), TEST_DATA(PQC_CIPHER_ML_KEM_1024),
        TEST_DATA(PQC_CIPHER_SLH_DSA_SHAKE_128F), TEST_DATA(PQC_CIPHER_SLH_DSA_SHAKE_128S),
        TEST_DATA(PQC_CIPHER_SLH_DSA_SHAKE_192F), TEST_DATA(PQC_CIPHER_SLH_DSA_SHAKE_192S),
        TEST_DATA(PQC_CIPHER_SLH_DSA_SHAKE_256F), TEST_DATA(PQC_CIPHER_SLH_DSA_SHAKE_256S)
    ),
    TestDataToString
);
