#include <gtest/gtest.h>

#include <pqc/aes.h>
#include <pqc/falcon.h>
#include <pqc/sha3.h>

TEST(PQ, PQC_badCipher)
{
    uint8_t key[PQC_AES_KEYLEN] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6',
                                  '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2'};

    EXPECT_EQ(PQC_init_context(100500, key, 32), PQC_BAD_CIPHER) << "Should return error for unknown cipher";
    uint8_t iv[PQC_AES_IVLEN] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};


    EXPECT_EQ(PQC_init_context(100500, key, PQC_AES_KEYLEN), PQC_BAD_CIPHER) << "Should return error for unknown cipher";

    EXPECT_EQ(PQC_init_context_iv(100500, key, PQC_AES_KEYLEN, iv, PQC_AES_IVLEN), PQC_BAD_CIPHER)
        << "Should return error for unknown cipher";

    EXPECT_EQ(PQC_init_context_hash(PQC_CIPHER_AES, PQC_SHA3_256), PQC_BAD_CIPHER)
        << "AES could not be used as hash function";
    EXPECT_EQ(PQC_init_context_hash(PQC_CIPHER_FALCON, PQC_SHA3_256), PQC_BAD_CIPHER)
        << "Falcon could not be used as hash function";

    EXPECT_EQ(PQC_init_context(PQC_CIPHER_SHA3, key, PQC_AES_KEYLEN), PQC_BAD_CIPHER)
        << "SHA3 could not be used with password";
    EXPECT_EQ(PQC_init_context_iv(PQC_CIPHER_SHA3, key, PQC_AES_KEYLEN, iv, PQC_AES_IVLEN), PQC_BAD_CIPHER)
        << "SHA3 could not be used with password";
}

TEST(PQ, PQC_AES_BadChipher_Sign)
{
    CIPHER_HANDLE context;

    uint8_t key[PQC_AES_KEYLEN] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'A', 'B', 'C', 'D', 'E', 'F',
                                  'G', 'H', 'I', 'J', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'K', 'L'};

    const int data_len = PQC_AES_BLOCKLEN;
    uint8_t data[data_len] = {89, 234, 87, 91, 40, 83, 179, 255, 80, 66, 19, 45, 89, 0, 64, 123};
    uint8_t data_copy[data_len];
    memcpy(data_copy, data, data_len);

    /// Encode
    context = PQC_init_context(PQC_CIPHER_AES, key, PQC_AES_KEYLEN);
    EXPECT_NE(context, PQC_BAD_CIPHER) << "Initialization should pass";

    char message[] = "The quick brown fox jumps over the lazy dog."
                     "The quick brown fox jumps over the lazy dog?"
                     "The quick brown fox jumps over the lazy dog!"
                     "The quick brown fox jumps over the lazy dog...";

    pqc_falcon_signature signature;

    EXPECT_EQ(
        PQC_sign(context, (uint8_t *)message, strlen(message) + 1, (uint8_t *)&signature, sizeof(signature)),
        PQC_BAD_CIPHER
    ) << "AES do not support message signing";

    EXPECT_EQ(PQC_add_data(context, (uint8_t *)message, strlen(message) + 1), PQC_BAD_CIPHER)
        << "AES do not support message hashing";
    EXPECT_EQ(PQC_hash_size(context), 0) << "AES do not support message hashing";
    EXPECT_EQ(PQC_get_hash(context, (uint8_t *)message, strlen(message) + 1), PQC_BAD_CIPHER)
        << "AES do not support message hashing";
}

TEST(PQ, PQC_AES_BadChipher_Hash)
{
    CIPHER_HANDLE context;

    uint8_t key[PQC_AES_KEYLEN] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'A', 'B', 'C', 'D', 'E', 'F',
                                  'G', 'H', 'I', 'J', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'K', 'L'};

    const int data_len = PQC_AES_BLOCKLEN;
    uint8_t data[data_len] = {89, 234, 87, 91, 40, 83, 179, 255, 80, 66, 19, 45, 89, 0, 64, 123};
    uint8_t data_copy[data_len];
    memcpy(data_copy, data, data_len);

    /// Encode
    context = PQC_init_context(PQC_CIPHER_AES, key, PQC_AES_KEYLEN);
    EXPECT_NE(context, PQC_BAD_CIPHER) << "Initialization should pass";

    char message[] = "The quick brown fox jumps over the lazy dog."
                     "The quick brown fox jumps over the lazy dog?"
                     "The quick brown fox jumps over the lazy dog!"
                     "The quick brown fox jumps over the lazy dog...";

    EXPECT_EQ(PQC_add_data(context, (uint8_t *)message, strlen(message) + 1), PQC_BAD_CIPHER)
        << "AES do not support message hashing";
    EXPECT_EQ(PQC_hash_size(context), 0) << "AES do not support message hashing";
    EXPECT_EQ(PQC_get_hash(context, (uint8_t *)message, strlen(message) + 1), PQC_BAD_CIPHER)
        << "AES do not support message hashing";
}

#define FALCON_PRIVATE(x) std::vector<uint8_t> x(sizeof(pqc_falcon_private_key))
#define FALCON_PUBLIC(x) std::vector<uint8_t> x(sizeof(pqc_falcon_public_key))


TEST(PQ, PQC_BadChipher_Verify)
{
    FALCON_PRIVATE(priv_alice);
    FALCON_PUBLIC(pub_alice);

    EXPECT_EQ(
        PQC_generate_key_pair(
            PQC_CIPHER_FALCON, pub_alice.data(), pub_alice.size(), priv_alice.data(), priv_alice.size()
        ),
        PQC_OK
    ) << "key generation should succeed";

    CIPHER_HANDLE alice = PQC_init_context(PQC_CIPHER_FALCON, priv_alice.data(), priv_alice.size());
    EXPECT_NE(alice, PQC_BAD_CIPHER) << "context initialization should pass";

    char message[] = "The quick brown fox jumps over the lazy dog."
                     "The quick brown fox jumps over the lazy dog?"
                     "The quick brown fox jumps over the lazy dog!"
                     "The quick brown fox jumps over the lazy dog...";

    pqc_falcon_signature signature;

    EXPECT_EQ(PQC_sign(alice, (uint8_t *)message, strlen(message) + 1, (uint8_t *)&signature, sizeof(signature)), PQC_OK)
        << "signing should succeed";

    EXPECT_EQ(
        PQC_verify(
            PQC_CIPHER_AES, pub_alice.data(), pub_alice.size(), (uint8_t *)message, strlen(message) + 1,
            (uint8_t *)&signature, sizeof(signature)
        ),
        PQC_BAD_CIPHER
    ) << "AES can't be used for verification";

    EXPECT_EQ(
        PQC_verify(
            PQC_CIPHER_SHA3, pub_alice.data(), pub_alice.size(), (uint8_t *)message, strlen(message) + 1,
            (uint8_t *)&signature, sizeof(signature)
        ),
        PQC_BAD_CIPHER
    ) << "SHA3 can't be used for verification";

    EXPECT_EQ(PQC_add_data(alice, (uint8_t *)message, strlen(message) + 1), PQC_BAD_CIPHER)
        << "Falcon do not support message hashing";
    EXPECT_EQ(PQC_hash_size(alice), 0) << "Falcon do not support message hashing";
    EXPECT_EQ(PQC_get_hash(alice, (uint8_t *)message, strlen(message) + 1), PQC_BAD_CIPHER)
        << "Falcon do not support message hashing";
}

TEST(PQ, PQC_SHA3_BadChipher)
{
    CIPHER_HANDLE handle = PQC_init_context_hash(PQC_CIPHER_SHA3, PQC_SHA3_512);

    char message[] = "The quick brown fox jumps over the lazy dog."
                     "The quick brown fox jumps over the lazy dog?"
                     "The quick brown fox jumps over the lazy dog!"
                     "The quick brown fox jumps over the lazy dog...";

    pqc_falcon_signature signature;

    EXPECT_EQ(
        PQC_sign(handle, (uint8_t *)message, strlen(message) + 1, (uint8_t *)&signature, sizeof(signature)),
        PQC_BAD_CIPHER
    ) << "SHA3 could not be used for message signing";

    EXPECT_EQ(PQC_encrypt(handle, PQC_SHA3_512, (uint8_t *)message, strlen(message)), PQC_BAD_CIPHER)
        << "SHA3 can't be used for encryption";
    EXPECT_EQ(PQC_decrypt(handle, PQC_SHA3_512, (uint8_t *)message, strlen(message)), PQC_BAD_CIPHER)
        << "SHA3 can't be used for encryption";
}
