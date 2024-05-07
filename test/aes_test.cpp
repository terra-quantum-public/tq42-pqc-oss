#include <gtest/gtest.h>

#include <pqc/aes.h>

TEST(AES, AES_init_badSize)
{
    CIPHER_HANDLE context;

    uint8_t key[PQC_AES_KEYLEN] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6',
                                  '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2'};

    context = PQC_init_context(PQC_CIPHER_AES, key, PQC_AES_KEYLEN - 1);

    EXPECT_EQ(context, PQC_BAD_CIPHER) << "Initialization should fail due to bad key size";
}

TEST(AES, AES_ECB_badSize)
{
    CIPHER_HANDLE context;

    uint8_t key[PQC_AES_KEYLEN] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6',
                                  '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2'};

    const int data_len = PQC_AES_BLOCKLEN * 3;
    uint8_t data[data_len] = {0};

    context = PQC_init_context(PQC_CIPHER_AES, key, PQC_AES_KEYLEN);

    EXPECT_NE(context, PQC_BAD_CIPHER) << "Initialization should pass";

    EXPECT_EQ(PQC_encrypt(context, PQC_AES_M_ECB, data, data_len), PQC_BAD_LEN)
        << "ECB mechanism accept only data blocks of size == PQC_AES_BLOCKLEN, so we should return PG_BAD_LEN";

    EXPECT_EQ(PQC_close_context(context), PQC_OK) << "Deinitialization should pass";
}

TEST(AES, AES_ECB_encodeDecode)
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

    EXPECT_EQ(PQC_encrypt(context, PQC_AES_M_ECB, data, data_len), PQC_OK) << "Encryption should pass";

    EXPECT_NE(memcmp(data, data_copy, PQC_AES_BLOCKLEN), 0) << "Data should change after encryption";

    /// Decode

    EXPECT_EQ(PQC_decrypt(context, PQC_AES_M_ECB, data, data_len), PQC_OK) << "Decryption should pass";

    EXPECT_EQ(memcmp(data, data_copy, PQC_AES_BLOCKLEN), 0) << "Data should be all zeros again after decryption";

    EXPECT_EQ(PQC_close_context(context), PQC_OK) << "Deinitialization should pass";
}

TEST(AES, AES_CBC_badSize)
{
    CIPHER_HANDLE context;

    uint8_t key[PQC_AES_KEYLEN] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6',
                                  '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2'};

    const int data_len = PQC_AES_BLOCKLEN * 3 + 1;
    uint8_t data[data_len] = {0};

    uint8_t iv[PQC_AES_IVLEN] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

    context = PQC_init_context_iv(PQC_CIPHER_AES, key, PQC_AES_KEYLEN, iv, PQC_AES_IVLEN);

    EXPECT_NE(context, PQC_BAD_CIPHER) << "Initialization should pass";

    EXPECT_EQ(PQC_encrypt(context, PQC_AES_M_CBC, data, data_len), PQC_BAD_LEN)
        << "ECB mechanism accept only data blocks of size == PQC_AES_BLOCKLEN, so we should return PG_BAD_LEN";

    EXPECT_EQ(PQC_close_context(context), PQC_OK) << "Deinitialization should pass";
}

TEST(AES, AES_CBC_encodeDecode)
{
    CIPHER_HANDLE context;

    uint8_t key[PQC_AES_KEYLEN] = {1,   2,   3,   4,   5,  6,  7,  8,  9,  10, '1', '2', '3', '4', '5', '6',
                                  '7', '8', '9', '0', 21, 22, 23, 24, 25, 26, 27,  28,  29,  30,  'A', 'B'};

    const int data_len = PQC_AES_BLOCKLEN * 2;

    uint8_t data[data_len] = {88, 16, 49, 23, 78, 30, 17, 99, 253, 164, 82, 97, 188, 87, 61, 13};
    uint8_t data_copy[data_len];
    memcpy(data_copy, data, data_len);

    uint8_t iv[PQC_AES_IVLEN] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

    /// Encoding

    context = PQC_init_context_iv(PQC_CIPHER_AES, key, PQC_AES_KEYLEN, iv, PQC_AES_IVLEN);
    EXPECT_NE(context, PQC_BAD_CIPHER) << "Initialization should pass";

    EXPECT_EQ(PQC_encrypt(context, PQC_AES_M_CBC, data, data_len), PQC_OK) << "Encryption should pass";

    EXPECT_NE(memcmp(data, data_copy, PQC_AES_BLOCKLEN), 0) << "Data should change after encryption";

    EXPECT_EQ(PQC_close_context(context), PQC_OK) << "Deinitialization should pass";

    /// Decoding

    context = PQC_init_context_iv(PQC_CIPHER_AES, key, PQC_AES_KEYLEN, iv, PQC_AES_IVLEN);
    EXPECT_NE(context, PQC_BAD_CIPHER) << "Initialization should pass";

    EXPECT_EQ(PQC_decrypt(context, PQC_AES_M_CBC, data, data_len), PQC_OK) << "Decryption should pass";

    EXPECT_EQ(memcmp(data, data_copy, PQC_AES_BLOCKLEN), 0) << "Data should match original after decryption";

    EXPECT_EQ(PQC_close_context(context), PQC_OK) << "Deinitialization should pass";
}

TEST(AES, AES_CBC_encodeDecode_parallel_context)
{
    CIPHER_HANDLE context;
    CIPHER_HANDLE context2;

    uint8_t key[PQC_AES_KEYLEN] = {1,   2,   3,   4,   5,  6,  7,  8,  9,  10, '1', '2', '3', '4', '5', '6',
                                  '7', '8', '9', '0', 21, 22, 23, 24, 25, 26, 27,  28,  29,  30,  'A', 'B'};

    const int data_len = PQC_AES_BLOCKLEN * 2;

    uint8_t data[data_len] = {88, 16, 49, 23, 78, 30, 17, 99, 253, 164, 82, 97, 188, 87, 61, 13};
    uint8_t data_copy[data_len];
    memcpy(data_copy, data, data_len);

    uint8_t iv[PQC_AES_IVLEN] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

    /// Encoding

    context = PQC_init_context_iv(PQC_CIPHER_AES, key, PQC_AES_KEYLEN, iv, PQC_AES_IVLEN);
    EXPECT_NE(context, PQC_BAD_CIPHER) << "Initialization should pass";

    EXPECT_EQ(PQC_encrypt(context, PQC_AES_M_CBC, data, data_len), PQC_OK) << "Encryption should pass";

    EXPECT_NE(memcmp(data, data_copy, PQC_AES_BLOCKLEN), 0) << "Data should change after encryption";


    /// Decoding

    context2 = PQC_init_context_iv(PQC_CIPHER_AES, key, PQC_AES_KEYLEN, iv, PQC_AES_IVLEN);
    EXPECT_NE(context2, PQC_BAD_CIPHER) << "Initialization should pass";

    EXPECT_EQ(PQC_decrypt(context2, PQC_AES_M_CBC, data, data_len), PQC_OK) << "Decryption should pass";

    EXPECT_EQ(memcmp(data, data_copy, PQC_AES_BLOCKLEN), 0) << "Data should match original after decryption";


    EXPECT_EQ(PQC_close_context(context), PQC_OK) << "Deinitialization should pass";

    EXPECT_EQ(PQC_close_context(context2), PQC_OK) << "Deinitialization should pass";
}


TEST(AES, AES_CBC_require_iv)
{
    CIPHER_HANDLE context;

    uint8_t key[PQC_AES_KEYLEN] = {1,   2,   3,   4,   5,  6,  7,  8,  9,  10, '1', '2', '3', '4', '5', '6',
                                  '7', '8', '9', '0', 21, 22, 23, 24, 25, 26, 27,  28,  29,  30,  'A', 'B'};

    const int data_len = PQC_AES_BLOCKLEN * 2;

    uint8_t data[data_len] = {88, 16, 49, 23, 78, 30, 17, 99, 253, 164, 82, 97, 188, 87, 61, 13};
    uint8_t data_copy[data_len];
    memcpy(data_copy, data, data_len);

    /// Encoding

    context = PQC_init_context(PQC_CIPHER_AES, key, PQC_AES_KEYLEN);
    EXPECT_NE(context, PQC_BAD_CIPHER) << "Initialization should pass";

    EXPECT_EQ(PQC_encrypt(context, PQC_AES_M_CBC, data, data_len), PQC_NO_IV) << "Encryption should fail, IV not set";

    /// Decoding

    context = PQC_init_context(PQC_CIPHER_AES, key, PQC_AES_KEYLEN);
    EXPECT_NE(context, PQC_BAD_CIPHER) << "Initialization should pass";

    EXPECT_EQ(PQC_decrypt(context, PQC_AES_M_CBC, data, data_len), PQC_NO_IV) << "Decryption should fail, IV not set";
}

TEST(AES, AES_OFB_require_iv)
{
    CIPHER_HANDLE context;

    uint8_t key[PQC_AES_KEYLEN] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'A', 'B', 'C', 'D', 'E', 'F',
                                  'G', 'H', 'I', 'J', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'K', 'L'};

    const int data_len = 12;

    uint8_t data[data_len] = {'H', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '!'};
    uint8_t data_copy[data_len];
    memcpy(data_copy, data, data_len);


    /// Encoding

    context = PQC_init_context(PQC_CIPHER_AES, key, PQC_AES_KEYLEN);
    EXPECT_NE(context, PQC_BAD_CIPHER) << "Initialization should pass";


    EXPECT_EQ(PQC_encrypt(context, PQC_AES_M_OFB, data, data_len), PQC_NO_IV) << "Encryption should fail, IV not set";

    /// Decoding
    context = PQC_init_context(PQC_CIPHER_AES, key, PQC_AES_KEYLEN);
    EXPECT_NE(context, PQC_BAD_CIPHER) << "Initialization should pass";

    EXPECT_EQ(PQC_decrypt(context, PQC_AES_M_OFB, data, data_len), PQC_NO_IV) << "Decryption should fail, IV not set";
}

TEST(AES, AES_OFB_encodeDecode)
{
    CIPHER_HANDLE context;

    uint8_t key[PQC_AES_KEYLEN] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 11,  12,  13,  14,  15, 16,
                                  17,  18,  19,  20,  '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 31, 32};

    const int data_len = PQC_AES_BLOCKLEN * 2;

    uint8_t data[data_len] = {24, 76, 85, 125, 230, 234, 78, 42, 58, 39, 11, 9, 7, 12, 18, 74};
    uint8_t data_copy[data_len];
    memcpy(data_copy, data, data_len);

    uint8_t iv[PQC_AES_IVLEN] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

    /// Encoding

    context = PQC_init_context_iv(PQC_CIPHER_AES, key, PQC_AES_KEYLEN, iv, PQC_AES_IVLEN);
    EXPECT_NE(context, PQC_BAD_CIPHER) << "Initialization should pass";

    EXPECT_EQ(PQC_encrypt(context, PQC_AES_M_OFB, data, data_len), PQC_OK) << "Encryption should pass";

    EXPECT_NE(memcmp(data, data_copy, PQC_AES_BLOCKLEN), 0) << "Data should change after encryption";

    EXPECT_EQ(PQC_close_context(context), PQC_OK) << "Deinitialization should pass";

    /// Decoding

    context = PQC_init_context_iv(PQC_CIPHER_AES, key, PQC_AES_KEYLEN, iv, PQC_AES_IVLEN);
    EXPECT_NE(context, PQC_BAD_CIPHER) << "Initialization should pass";

    EXPECT_EQ(PQC_decrypt(context, PQC_AES_M_OFB, data, data_len), PQC_OK) << "Decryption should pass";

    EXPECT_EQ(memcmp(data, data_copy, PQC_AES_BLOCKLEN), 0) << "Data should match original after decryption";

    EXPECT_EQ(PQC_close_context(context), PQC_OK) << "Deinitialization should pass";
}

TEST(AES, AES_OFB2_encodeDecode)
{
    CIPHER_HANDLE context;

    uint8_t key[PQC_AES_KEYLEN] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'A', 'B', 'C', 'D', 'E', 'F',
                                  'G', 'H', 'I', 'J', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'K', 'L'};

    const int data_len = PQC_AES_BLOCKLEN + 1;
    uint8_t data[data_len] = {89, 234, 87, 91, 40, 83, 179, 255, 80, 66, 19, 45, 89, 0, 64, 78, 1};
    uint8_t data_copy[data_len];
    memcpy(data_copy, data, data_len);

    /// Encode
    uint8_t iv[PQC_AES_IVLEN] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    context = PQC_init_context_iv(PQC_CIPHER_AES, key, PQC_AES_KEYLEN, iv, PQC_AES_IVLEN);

    EXPECT_NE(context, PQC_BAD_CIPHER) << "Initialization should pass";

    EXPECT_EQ(PQC_encrypt(context, PQC_AES_M_OFB, data, data_len), PQC_OK) << "Encryption should pass";

    EXPECT_NE(memcmp(data, data_copy, data_len), 0) << "Data should change after encryption";

    /// Decode

    EXPECT_EQ(PQC_decrypt(context, PQC_AES_M_OFB, data, data_len), PQC_OK) << "Decryption should pass";

    EXPECT_EQ(memcmp(data, data_copy, data_len), 0) << "Data should be all zeros again after decryption";

    EXPECT_EQ(PQC_close_context(context), PQC_OK) << "Deinitialization should pass";
}

TEST(AES, AES_CTR_require_iv)
{
    CIPHER_HANDLE context;

    uint8_t key[PQC_AES_KEYLEN] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'A', 'B', 'C', 'D', 'E', 'F',
                                  'G', 'H', 'I', 'J', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'K', 'L'};

    const int data_len = 12;

    uint8_t data[data_len] = {'H', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '!'};
    uint8_t data_copy[data_len];
    memcpy(data_copy, data, data_len);


    /// Encoding

    context = PQC_init_context(PQC_CIPHER_AES, key, PQC_AES_KEYLEN);
    EXPECT_NE(context, PQC_BAD_CIPHER) << "Initialization should pass";


    EXPECT_EQ(PQC_encrypt(context, PQC_AES_M_CTR, data, data_len), PQC_NO_IV) << "Encryption should fail, IV not set";

    /// Decoding
    context = PQC_init_context(PQC_CIPHER_AES, key, PQC_AES_KEYLEN);
    EXPECT_NE(context, PQC_BAD_CIPHER) << "Initialization should pass";

    EXPECT_EQ(PQC_decrypt(context, PQC_AES_M_CTR, data, data_len), PQC_NO_IV) << "Decryption should fail, IV not set";
}


TEST(AES, AES_CTR_encodeDecode)
{
    CIPHER_HANDLE context;

    uint8_t key[PQC_AES_KEYLEN] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'A', 'B', 'C', 'D', 'E', 'F',
                                  'G', 'H', 'I', 'J', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'K', 'L'};

    const int data_len = PQC_AES_BLOCKLEN - 1;
    uint8_t data[data_len] = {89, 234, 87, 91, 40, 83, 179, 255, 80, 66, 19, 45, 89, 0, 64};
    uint8_t iv[PQC_AES_IVLEN] = {0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,
                                0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF};

    uint8_t data_copy[data_len];
    memcpy(data_copy, data, data_len);

    /// Encode
    context = PQC_init_context_iv(PQC_CIPHER_AES, key, PQC_AES_KEYLEN, iv, PQC_AES_IVLEN);
    EXPECT_NE(context, PQC_BAD_CIPHER) << "Initialization should pass";

    EXPECT_EQ(PQC_encrypt(context, PQC_AES_M_CTR, data, data_len), PQC_OK) << "Encryption should pass";

    EXPECT_NE(memcmp(data, data_copy, data_len), 0) << "Data should change after encryption";

    PQC_close_context(context);

    /// Decode

    context = PQC_init_context_iv(PQC_CIPHER_AES, key, PQC_AES_KEYLEN, iv, PQC_AES_IVLEN);
    EXPECT_NE(context, PQC_BAD_CIPHER) << "Initialization should pass";

    EXPECT_EQ(PQC_decrypt(context, PQC_AES_M_CTR, data, data_len), PQC_OK) << "Decryption should pass";

    EXPECT_EQ(memcmp(data, data_copy, data_len), 0) << "Data should match original after decryption";

    EXPECT_EQ(PQC_close_context(context), PQC_OK) << "Deinitialization should pass";
}

TEST(AES, AES_CTR_counterOverflow)
{
    CIPHER_HANDLE context;

    uint8_t key[PQC_AES_KEYLEN] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'A', 'B', 'C', 'D', 'E', 'F',
                                  'G', 'H', 'I', 'J', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'K', 'L'};

    uint8_t iv[PQC_AES_IVLEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    uint8_t data[PQC_AES_BLOCKLEN * 2] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    // Create expected data
    // As input data is all zeros, output of CTR will be exaclty counter encrypted by AES
    // For first block counter is FF..FF, for next, it is 00...00
    uint8_t expected[PQC_AES_BLOCKLEN * 2] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    context = PQC_init_context(PQC_CIPHER_AES, key, PQC_AES_KEYLEN);
    EXPECT_NE(context, PQC_BAD_CIPHER) << "Initialization should pass";

    // Now we encrypt counters using ECB to get expected data.
    EXPECT_EQ(PQC_encrypt(context, PQC_AES_M_ECB, expected, PQC_AES_BLOCKLEN), PQC_OK) << "Encryption should pass";
    EXPECT_EQ(PQC_encrypt(context, PQC_AES_M_ECB, expected + PQC_AES_BLOCKLEN, PQC_AES_BLOCKLEN), PQC_OK)
        << "Encryption should pass";

    PQC_close_context(context);

    /// Now we test operation of CTR
    context = PQC_init_context_iv(PQC_CIPHER_AES, key, PQC_AES_KEYLEN, iv, PQC_AES_IVLEN);
    EXPECT_NE(context, PQC_BAD_CIPHER) << "Initialization should pass";

    EXPECT_EQ(PQC_encrypt(context, PQC_AES_M_CTR, data, PQC_AES_BLOCKLEN * 2), PQC_OK) << "Encryption should pass";

    EXPECT_EQ(memcmp(data, expected, PQC_AES_BLOCKLEN * 2), 0) << "Ciphertext should match expectation";

    PQC_close_context(context);
}


TEST(AES, AES_CTR_encode_partial)
{
    CIPHER_HANDLE context;

    constexpr int data_len = 64;

    uint8_t ciphertext[data_len] = {0x60, 0x1E, 0xC3, 0x13, 0x77, 0x57, 0x89, 0xA5, 0xB7, 0xA7, 0xF5, 0x04, 0xBB,
                                    0xF3, 0xD2, 0x28, 0xF4, 0x43, 0xE3, 0xCA, 0x4D, 0x62, 0xB5, 0x9A, 0xCA, 0x84,
                                    0xE9, 0x90, 0xCA, 0xCA, 0xF5, 0xC5, 0x2B, 0x09, 0x30, 0xDA, 0xA2, 0x3D, 0xE9,
                                    0x4C, 0xE8, 0x70, 0x17, 0xBA, 0x2D, 0x84, 0x98, 0x8D, 0xDF, 0xC9, 0xC5, 0x8D,
                                    0xB6, 0x7A, 0xAD, 0xA6, 0x13, 0xC2, 0xDD, 0x08, 0x45, 0x79, 0x41, 0xA6};

    uint8_t key[PQC_AES_KEYLEN] = {0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE,
                                  0xF0, 0x85, 0x7D, 0x77, 0x81, 0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61,
                                  0x08, 0xD7, 0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4};
    uint8_t iv[PQC_AES_IVLEN] = {0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,
                                0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF};


    for (int step = 1; step < data_len; ++step)
    {
        uint8_t data[data_len] = {0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73,
                                  0x93, 0x17, 0x2A, 0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7,
                                  0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51, 0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4,
                                  0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF, 0xF6, 0x9F, 0x24, 0x45,
                                  0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10};

        context = PQC_init_context_iv(PQC_CIPHER_AES, key, PQC_AES_KEYLEN, iv, PQC_AES_IVLEN);
        EXPECT_NE(context, PQC_BAD_CIPHER) << "Initialization should pass";

        for (int i = 0; i < data_len; i += step)
        {
            size_t len = std::min(step, data_len - i);
            EXPECT_EQ(PQC_encrypt(context, PQC_AES_M_CTR, data + i, len), PQC_OK) << "Encryption should pass";
        }

        EXPECT_EQ(memcmp(data, ciphertext, data_len), 0) << "Ciphertext should match";
        PQC_close_context(context);
    }
}


class AES_test_data
{
public:
    AES_test_data(
        std::vector<uint8_t> plaintext, std::vector<uint8_t> ciphertext, std::vector<uint8_t> key,
        std::vector<uint8_t> iv, uint32_t mechanism
    )
        : _plaintext(plaintext), _ciphertext(ciphertext), _key(key), _iv(iv), _mechanism(mechanism)
    {
    }

    std::vector<uint8_t> _plaintext;
    std::vector<uint8_t> _ciphertext;
    std::vector<uint8_t> _key;
    std::vector<uint8_t> _iv;
    uint32_t _mechanism;
};


class AESVectorTestSuite : public testing::TestWithParam<AES_test_data>
{
};

TEST_P(AESVectorTestSuite, test_encrypt)
{
    AES_test_data param = GetParam();

    CIPHER_HANDLE context;
    if (param._iv.size() == 0)
    {
        context = PQC_init_context(PQC_CIPHER_AES, param._key.data(), PQC_AES_KEYLEN);
    }
    else
    {
        context =
            PQC_init_context_iv(PQC_CIPHER_AES, param._key.data(), PQC_AES_KEYLEN, param._iv.data(), param._iv.size());
    }

    EXPECT_NE(context, PQC_BAD_CIPHER) << "Initialization should pass";

    EXPECT_EQ(PQC_encrypt(context, param._mechanism, param._plaintext.data(), param._plaintext.size()), PQC_OK)
        << "Encryption should pass";

    EXPECT_EQ(memcmp(param._plaintext.data(), param._ciphertext.data(), param._plaintext.size()), 0)
        << "Encrypted data should match expected vector";

    PQC_close_context(context);
}

TEST_P(AESVectorTestSuite, test_decrypt)
{
    AES_test_data param = GetParam();

    CIPHER_HANDLE context;
    if (param._iv.size() == 0)
    {
        context = PQC_init_context(PQC_CIPHER_AES, param._key.data(), PQC_AES_KEYLEN);
    }
    else
    {
        context =
            PQC_init_context_iv(PQC_CIPHER_AES, param._key.data(), PQC_AES_KEYLEN, param._iv.data(), param._iv.size());
    }
    EXPECT_NE(context, PQC_BAD_CIPHER) << "Initialization should pass";

    EXPECT_EQ(PQC_decrypt(context, param._mechanism, param._ciphertext.data(), param._ciphertext.size()), PQC_OK)
        << "Encryption should pass";

    EXPECT_EQ(memcmp(param._ciphertext.data(), param._plaintext.data(), param._plaintext.size()), 0)
        << "Encrypted data should match expected vector";

    PQC_close_context(context);
}


INSTANTIATE_TEST_SUITE_P(
    AES, AESVectorTestSuite,
    testing::Values(
        AES_test_data(
            {0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A},
            {0xF3, 0xEE, 0xD1, 0xBD, 0xB5, 0xD2, 0xA0, 0x3C, 0x06, 0x4B, 0x5A, 0x7E, 0x3D, 0xB1, 0x81, 0xF8},
            {0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
             0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7, 0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4},
            {}, PQC_AES_M_ECB
        ),
        AES_test_data(
            {0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51},
            {0x59, 0x1C, 0xCB, 0x10, 0xD4, 0x10, 0xED, 0x26, 0xDC, 0x5B, 0xA7, 0x4A, 0x31, 0x36, 0x28, 0x70},
            {0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
             0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7, 0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4},
            {}, PQC_AES_M_ECB
        ),
        AES_test_data(
            {0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF},
            {0xB6, 0xED, 0x21, 0xB9, 0x9C, 0xA6, 0xF4, 0xF9, 0xF1, 0x53, 0xE7, 0xB1, 0xBE, 0xAF, 0xED, 0x1D},
            {0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
             0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7, 0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4},
            {}, PQC_AES_M_ECB
        ),
        AES_test_data(
            {0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10},
            {0x23, 0x30, 0x4B, 0x7A, 0x39, 0xF9, 0xF3, 0xFF, 0x06, 0x7D, 0x8D, 0x8F, 0x9E, 0x24, 0xEC, 0xC7},
            {0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
             0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7, 0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4},
            {}, PQC_AES_M_ECB
        ),

        AES_test_data(
            {0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
             0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
             0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
             0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10},
            {0xF5, 0x8C, 0x4C, 0x04, 0xD6, 0xE5, 0xF1, 0xBA, 0x77, 0x9E, 0xAB, 0xFB, 0x5F, 0x7B, 0xFB, 0xD6,
             0x9C, 0xFC, 0x4E, 0x96, 0x7E, 0xDB, 0x80, 0x8D, 0x67, 0x9F, 0x77, 0x7B, 0xC6, 0x70, 0x2C, 0x7D,
             0x39, 0xF2, 0x33, 0x69, 0xA9, 0xD9, 0xBA, 0xCF, 0xA5, 0x30, 0xE2, 0x63, 0x04, 0x23, 0x14, 0x61,
             0xB2, 0xEB, 0x05, 0xE2, 0xC3, 0x9B, 0xE9, 0xFC, 0xDA, 0x6C, 0x19, 0x07, 0x8C, 0x6A, 0x9D, 0x1B},
            {0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
             0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7, 0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4},
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
            PQC_AES_M_CBC
        ),

        AES_test_data(
            {0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
             0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
             0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
             0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10},
            {0xDC, 0x7E, 0x84, 0xBF, 0xDA, 0x79, 0x16, 0x4B, 0x7E, 0xCD, 0x84, 0x86, 0x98, 0x5D, 0x38, 0x60,
             0x4F, 0xEB, 0xDC, 0x67, 0x40, 0xD2, 0x0B, 0x3A, 0xC8, 0x8F, 0x6A, 0xD8, 0x2A, 0x4F, 0xB0, 0x8D,
             0x71, 0xAB, 0x47, 0xA0, 0x86, 0xE8, 0x6E, 0xED, 0xF3, 0x9D, 0x1C, 0x5B, 0xBA, 0x97, 0xC4, 0x08,
             0x01, 0x26, 0x14, 0x1D, 0x67, 0xF3, 0x7B, 0xE8, 0x53, 0x8F, 0x5A, 0x8B, 0xE7, 0x40, 0xE4, 0x84},
            {0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
             0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7, 0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4},
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
            PQC_AES_M_OFB
        ),

        AES_test_data(
            {0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
             0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
             0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
             0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10},
            {0x60, 0x1E, 0xC3, 0x13, 0x77, 0x57, 0x89, 0xA5, 0xB7, 0xA7, 0xF5, 0x04, 0xBB, 0xF3, 0xD2, 0x28,
             0xF4, 0x43, 0xE3, 0xCA, 0x4D, 0x62, 0xB5, 0x9A, 0xCA, 0x84, 0xE9, 0x90, 0xCA, 0xCA, 0xF5, 0xC5,
             0x2B, 0x09, 0x30, 0xDA, 0xA2, 0x3D, 0xE9, 0x4C, 0xE8, 0x70, 0x17, 0xBA, 0x2D, 0x84, 0x98, 0x8D,
             0xDF, 0xC9, 0xC5, 0x8D, 0xB6, 0x7A, 0xAD, 0xA6, 0x13, 0xC2, 0xDD, 0x08, 0x45, 0x79, 0x41, 0xA6},
            {0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
             0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7, 0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4},
            {0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF},
            PQC_AES_M_CTR
        )

    )
);