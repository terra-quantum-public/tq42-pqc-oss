#include <chrono>
#include <cmath>
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


const auto max_mutation_test_time = std::chrono::seconds(30);

class Signing_test_data
{
public:
    Signing_test_data(uint32_t cipher, std::string name) : _cipher(cipher), _name(name) {}

    uint32_t _cipher;
    std::string _name;
};

#define TEST_DATA(cipher) Signing_test_data(cipher, #cipher)


class SigningTestSuite : public testing::TestWithParam<Signing_test_data>
{
public:
    uint32_t cipher() { return GetParam()._cipher; }
    size_t private_size() { return PQC_cipher_get_length(cipher(), PQC_LENGTH_PRIVATE); }
    size_t public_size() { return PQC_cipher_get_length(cipher(), PQC_LENGTH_PUBLIC); }
    size_t signature_size() { return PQC_cipher_get_length(cipher(), PQC_LENGTH_SIGNATURE); }
};


TEST_P(SigningTestSuite, CHECK_SIGNATURE_SIZE)
{
    std::vector<uint8_t> private_key(private_size(), 0);
    std::vector<uint8_t> public_key(public_size(), 0);
    std::vector<uint8_t> signature(signature_size(), 0);

    CIPHER_HANDLE handle = PQC_context_init_asymmetric(
        cipher(), public_key.data(), public_key.size(), private_key.data(), private_key.size()
    );

    EXPECT_NE(handle, PQC_BAD_CIPHER) << "Initialization should pass";

    char message[] = "The quick brown fox jumps over the lazy dog.";

    EXPECT_EQ(
        PQC_signature_create(handle, (uint8_t *)message, strlen(message) + 1, signature.data(), signature.size() - 1),
        PQC_BAD_LEN
    ) << "signing should fail due to bad signature size";

    PQC_context_close(handle);
}

TEST_P(SigningTestSuite, CHECK_CREATE_SIGNATURE_KEY_SET)
{
    std::vector<uint8_t> private_key(private_size(), 0);
    std::vector<uint8_t> public_key(public_size(), 0);
    std::vector<uint8_t> signature(signature_size(), 0);

    CIPHER_HANDLE handle = PQC_context_init_asymmetric(cipher(), nullptr, 0, nullptr, 0);

    EXPECT_NE(handle, PQC_BAD_CIPHER) << "Initialization should pass";

    char message[] = "The quick brown fox jumps over the lazy dog.";

    EXPECT_EQ(
        PQC_signature_create(handle, (uint8_t *)message, strlen(message) + 1, signature.data(), signature.size()),
        PQC_KEY_NOT_SET
    ) << "signing should fail due to absent key";

    PQC_context_close(handle);
}

TEST_P(SigningTestSuite, VERIFY_CHECK_SIGNATURE_SIZE)
{
    std::vector<uint8_t> public_key(public_size(), 0);
    std::vector<uint8_t> signature(signature_size(), 0);

    CIPHER_HANDLE handle = PQC_context_init_asymmetric(cipher(), public_key.data(), public_key.size(), nullptr, 0);

    char message[] = "The quick brown fox jumps over the lazy dog.";

    EXPECT_EQ(
        PQC_signature_verify(handle, (uint8_t *)message, strlen(message) + 1, signature.data(), signature.size() - 1),
        PQC_BAD_LEN
    ) << "should fail due to bad signature size";

    PQC_context_close(handle);
}

TEST_P(SigningTestSuite, VERIFY_CHECK_KEY_SET)
{
    std::vector<uint8_t> signature(signature_size(), 0);

    CIPHER_HANDLE handle = PQC_context_init_asymmetric(cipher(), nullptr, 0, nullptr, 0);

    char message[] = "The quick brown fox jumps over the lazy dog.";

    EXPECT_EQ(
        PQC_signature_verify(handle, (uint8_t *)message, strlen(message) + 1, signature.data(), signature.size()),
        PQC_KEY_NOT_SET
    ) << "should fail due to missing public key in context";

    PQC_context_close(handle);
}

TEST_P(SigningTestSuite, CHECK_SIGNATURE)
{
    std::vector<uint8_t> public_key(public_size(), 0);
    std::vector<uint8_t> signature(signature_size(), 0);

    CIPHER_HANDLE alice = PQC_context_init_asymmetric(cipher(), nullptr, 0, nullptr, 0);
    EXPECT_NE(alice, PQC_BAD_CIPHER) << "context initialization should pass";

    EXPECT_EQ(PQC_context_keypair_generate(alice), PQC_OK) << "key generation should succeed";

    EXPECT_EQ(PQC_context_get_public_key(alice, public_key.data(), public_key.size()), PQC_OK)
        << "PQC_context_get_public_key should return OK";

    CIPHER_HANDLE bob = PQC_context_init_asymmetric(cipher(), public_key.data(), public_key.size(), nullptr, 0);
    EXPECT_NE(bob, PQC_BAD_CIPHER) << "context initialization should pass";

    char message[] = "The quick brown fox jumps over the lazy dog."
                     "The quick brown fox jumps over the lazy dog?"
                     "The quick brown fox jumps over the lazy dog!"
                     "The quick brown fox jumps over the lazy dog...";

    EXPECT_EQ(
        PQC_signature_create(alice, (uint8_t *)message, strlen(message) + 1, signature.data(), signature.size()), PQC_OK
    ) << "signing should succeed";

    EXPECT_EQ(
        PQC_signature_verify(bob, (uint8_t *)message, strlen(message) + 1, signature.data(), signature.size()), PQC_OK
    ) << "signature should match";

    PQC_context_close(alice);
    PQC_context_close(bob);
}

TEST_P(SigningTestSuite, BAD_SIGNATURE)
{
    std::vector<uint8_t> public_key(public_size(), 0);
    std::vector<uint8_t> signature(signature_size(), 0);

    CIPHER_HANDLE alice = PQC_context_init_asymmetric(cipher(), nullptr, 0, nullptr, 0);
    EXPECT_NE(alice, PQC_BAD_CIPHER) << "context initialization should pass";

    EXPECT_EQ(PQC_context_keypair_generate(alice), PQC_OK) << "key generation should succeed";

    EXPECT_EQ(PQC_context_get_public_key(alice, public_key.data(), public_key.size()), PQC_OK)
        << "PQC_context_get_public_key should return OK";

    CIPHER_HANDLE bob = PQC_context_init_asymmetric(cipher(), public_key.data(), public_key.size(), nullptr, 0);
    EXPECT_NE(bob, PQC_BAD_CIPHER) << "context initialization should pass";

    char message[] = "The quick brown fox jumps over the lazy dog."
                     "The quick brown fox jumps over the lazy dog?"
                     "The quick brown fox jumps over the lazy dog!"
                     "The quick brown fox jumps over the lazy dog...";

    EXPECT_EQ(
        PQC_signature_create(alice, (uint8_t *)message, strlen(message) + 1, signature.data(), signature.size()), PQC_OK
    ) << "signing should succeed";

    EXPECT_EQ(
        PQC_signature_verify(bob, (uint8_t *)message, strlen(message) + 1, signature.data(), signature.size()), PQC_OK
    ) << "signature should match";

    const auto start = std::chrono::system_clock::now();

    size_t bits = signature.size() * 8;

    for (size_t i = 0; i < bits; ++i)
    {
        const size_t bit_index = ((size_t)floor((double)i * 0.68 * (double)bits)) % bits;
        const size_t byte = bit_index / 8;
        const size_t bit = bit_index % 8;

        signature[byte] ^= (1 << bit);

        EXPECT_EQ(
            PQC_signature_verify(bob, (uint8_t *)message, strlen(message) + 1, signature.data(), signature.size()),
            PQC_BAD_SIGNATURE
        ) << "changed signature should NOT match";

        signature[byte] ^= (1 << bit);

        const auto now = std::chrono::system_clock::now();

        if ((now - start) > max_mutation_test_time)
        {
            std::cout << "Mutations performed: " << i << std::endl;
            break;
        }
    }

    PQC_context_close(alice);
    PQC_context_close(bob);
}

TEST_P(SigningTestSuite, BAD_MESSAGE)
{
    std::vector<uint8_t> public_key(public_size(), 0);
    std::vector<uint8_t> signature(signature_size(), 0);

    CIPHER_HANDLE alice = PQC_context_init_asymmetric(cipher(), nullptr, 0, nullptr, 0);
    EXPECT_NE(alice, PQC_BAD_CIPHER) << "context initialization should pass";

    EXPECT_EQ(PQC_context_keypair_generate(alice), PQC_OK) << "key generation should succeed";

    EXPECT_EQ(PQC_context_get_public_key(alice, public_key.data(), public_key.size()), PQC_OK)
        << "PQC_context_get_public_key should return OK";

    CIPHER_HANDLE bob = PQC_context_init_asymmetric(cipher(), public_key.data(), public_key.size(), nullptr, 0);
    EXPECT_NE(bob, PQC_BAD_CIPHER) << "context initialization should pass";

    char message[] = "The quick brown fox jumps over the lazy dog.";

    const size_t message_len = strlen(message) + 1;

    EXPECT_EQ(PQC_signature_create(alice, (uint8_t *)message, message_len, signature.data(), signature.size()), PQC_OK)
        << "signing should succeed";

    EXPECT_EQ(PQC_signature_verify(bob, (uint8_t *)message, message_len, signature.data(), signature.size()), PQC_OK)
        << "signature should match";


    const auto start = std::chrono::system_clock::now();

    size_t bits = message_len * 8;

    for (size_t i = 0; i < bits; ++i)
    {
        const size_t bit_index = ((size_t)floor((double)i * 0.68 * (double)bits)) % bits;
        const size_t byte = bit_index / 8;
        const size_t bit = bit_index % 8;

        message[byte] ^= (1 << bit);

        EXPECT_EQ(
            PQC_signature_verify(bob, (uint8_t *)message, strlen(message) + 1, signature.data(), signature.size()),
            PQC_BAD_SIGNATURE
        ) << "changed message should NOT match";

        message[byte] ^= (1 << bit);

        const auto now = std::chrono::system_clock::now();

        if ((now - start) > max_mutation_test_time)
        {
            std::cout << "Mutations performed: " << i << std::endl;
            break;
        }
    }

    PQC_context_close(alice);
    PQC_context_close(bob);
}

static std::string TestDataToString(const testing::TestParamInfo<Signing_test_data> & info) { return info.param._name; }

INSTANTIATE_TEST_SUITE_P(
    Asymmetric, SigningTestSuite,
    testing::Values(
        TEST_DATA(PQC_CIPHER_DILITHIUM), TEST_DATA(PQC_CIPHER_FALCON), TEST_DATA(PQC_CIPHER_ML_DSA_44),
        TEST_DATA(PQC_CIPHER_ML_DSA_65), TEST_DATA(PQC_CIPHER_ML_DSA_87), TEST_DATA(PQC_CIPHER_SLH_DSA_SHAKE_128F),
        TEST_DATA(PQC_CIPHER_SLH_DSA_SHAKE_128S), TEST_DATA(PQC_CIPHER_SLH_DSA_SHAKE_192F),
        TEST_DATA(PQC_CIPHER_SLH_DSA_SHAKE_192S), TEST_DATA(PQC_CIPHER_SLH_DSA_SHAKE_256F),
        TEST_DATA(PQC_CIPHER_SLH_DSA_SHAKE_256S)
    ),
    TestDataToString
);
