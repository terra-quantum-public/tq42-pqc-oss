
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

class KEM_test_data
{
public:
    KEM_test_data(uint32_t cipher, std::string name) : _cipher(cipher), _name(name) {}

    uint32_t _cipher;
    std::string _name;
};

#define TEST_DATA(cipher) KEM_test_data(cipher, #cipher)

class KEMTestSuite : public testing::TestWithParam<KEM_test_data>
{
public:
    uint32_t cipher() { return GetParam()._cipher; }
    size_t private_size() { return PQC_cipher_get_length(cipher(), PQC_LENGTH_PRIVATE); }
    size_t public_size() { return PQC_cipher_get_length(cipher(), PQC_LENGTH_PUBLIC); }
    size_t shared_size() { return PQC_cipher_get_length(cipher(), PQC_LENGTH_SHARED); }
    size_t message_size() { return PQC_cipher_get_length(cipher(), PQC_LENGTH_MESSAGE); }
};

TEST_P(KEMTestSuite, CREATE_SECRET)
{
    std::vector<uint8_t> public_key(public_size(), 0);

    std::vector<uint8_t> shared_alice(shared_size(), 0);
    std::vector<uint8_t> shared_bob(shared_size(), 0);
    std::vector<uint8_t> message(message_size(), 0);

    CIPHER_HANDLE alice = PQC_context_init_asymmetric(cipher(), nullptr, 0, nullptr, 0);
    EXPECT_NE(alice, PQC_BAD_CIPHER) << "context initialization should pass";

    EXPECT_EQ(PQC_context_keypair_generate(alice), PQC_OK) << "key generation should succeed";

    EXPECT_EQ(PQC_context_get_public_key(alice, public_key.data(), public_key.size()), PQC_OK)
        << "PQC_context_get_public_key should return OK";

    CIPHER_HANDLE bob = PQC_context_init_asymmetric(cipher(), public_key.data(), public_key.size(), nullptr, 0);
    EXPECT_NE(bob, PQC_BAD_CIPHER) << "context initialization should pass";

    EXPECT_EQ(
        PQC_kem_encapsulate_secret(bob, message.data(), message.size(), shared_alice.data(), shared_alice.size()),
        PQC_OK
    );

    EXPECT_EQ(
        PQC_kem_decapsulate_secret(alice, message.data(), message.size(), shared_bob.data(), shared_alice.size()),
        PQC_OK
    );

    EXPECT_TRUE(shared_alice == shared_bob);

    PQC_context_close(alice);
    PQC_context_close(bob);
}

TEST_P(KEMTestSuite, ENCAPSULATE_DECAPSULATE)
{
    std::vector<uint8_t> public_key(public_size(), 0);

    std::vector<uint8_t> shared_alice(shared_size(), 0);
    std::vector<uint8_t> shared_bob(shared_size(), 0);
    std::vector<uint8_t> message(message_size(), 0);

    const size_t info_size = 10;
    uint8_t party_a_info[info_size] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};

    CIPHER_HANDLE alice = PQC_context_init_asymmetric(cipher(), nullptr, 0, nullptr, 0);
    EXPECT_NE(alice, PQC_BAD_CIPHER) << "context initialization should pass";

    EXPECT_EQ(PQC_context_keypair_generate(alice), PQC_OK) << "key generation should succeed";

    EXPECT_EQ(PQC_context_get_public_key(alice, public_key.data(), public_key.size()), PQC_OK)
        << "PQC_context_get_public_key should return OK";

    CIPHER_HANDLE bob = PQC_context_init_asymmetric(cipher(), public_key.data(), public_key.size(), nullptr, 0);
    EXPECT_NE(bob, PQC_BAD_CIPHER) << "context initialization should pass";

    EXPECT_EQ(
        PQC_kem_encapsulate(
            bob, message.data(), message.size(), party_a_info, info_size, shared_alice.data(), shared_alice.size()
        ),
        PQC_OK
    );

    EXPECT_EQ(
        PQC_kem_decapsulate(
            alice, message.data(), message.size(), party_a_info, info_size, shared_bob.data(), shared_alice.size()
        ),
        PQC_OK
    );

    EXPECT_TRUE(shared_alice == shared_bob);

    PQC_context_close(alice);
    PQC_context_close(bob);
}

static std::string TestDataToString(const testing::TestParamInfo<KEM_test_data> & info) { return info.param._name; }

INSTANTIATE_TEST_SUITE_P(
    Asymmetric, KEMTestSuite,
    testing::Values(
        TEST_DATA(PQC_CIPHER_KYBER_512), TEST_DATA(PQC_CIPHER_KYBER_768), TEST_DATA(PQC_CIPHER_KYBER_1024),
        TEST_DATA(PQC_CIPHER_MCELIECE), TEST_DATA(PQC_CIPHER_ML_KEM_512), TEST_DATA(PQC_CIPHER_ML_KEM_768),
        TEST_DATA(PQC_CIPHER_ML_KEM_1024)
    ),
    TestDataToString
);
