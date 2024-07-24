#include "pqc/kdf.h"
#include <gtest/gtest.h>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

std::vector<uint8_t> hex_to_bytes(const std::string & hex)
{
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2)
    {
        int high = std::stoi(hex.substr(i, 2), nullptr, 16);
        bytes.push_back(static_cast<uint8_t>(high));
    }
    return bytes;
}

TEST(PBKDF2, DerivedKeyCorrectnessSHA3_224)
{
    const uint8_t password[] = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
    const size_t password_length = sizeof(password) / sizeof(password[0]);
    const size_t master_key_length = 32 * 8;         // 32 bytes * 8 bits per byte
    uint8_t master_key[master_key_length / 8] = {0}; // Actual byte array

    std::string salt_hex = "a5dcea8d0bba2f1fcfa5824085bf06e65fa1255484dafd499984323672b71fee";
    std::vector<uint8_t> salt = hex_to_bytes(salt_hex);
    const size_t salt_length = salt.size();

    size_t hash_length = 224;
    size_t iterations = 10000;

    size_t result = PQC_pbkdf_2(
        PQC_PBKDF2_HMAC_SHA3, hash_length, password_length, password, master_key_length, master_key, sizeof(master_key),
        salt.data(), salt_length, iterations
    );

    std::vector<uint8_t> expected_key = {0xbd, 0x04, 0xbd, 0xd1, 0x15, 0xee, 0x11, 0xcc, 0x1e, 0xc9, 0x78,
                                         0xf7, 0xfe, 0xc2, 0xc8, 0xd6, 0xdc, 0x35, 0x7d, 0xd8, 0x44, 0x93,
                                         0x4f, 0x13, 0xe4, 0x2e, 0x9b, 0xae, 0x98, 0x69, 0x8e, 0x87};

    ASSERT_EQ(result, PQC_OK) << "Key derivation failed with error code: " << result;
    ASSERT_EQ(std::vector<uint8_t>(master_key, master_key + master_key_length / 8), expected_key)
        << "Derived key does not match expected key";
}


TEST(PBKDF2, DerivedKeyCorrectnessSHA3_256)
{
    const uint8_t password[] = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
    const size_t password_length = sizeof(password) / sizeof(password[0]);
    const size_t master_key_length = 32 * 8;         // 32 bytes * 8 bits per byte
    uint8_t master_key[master_key_length / 8] = {0}; // Actual byte array

    std::string salt_hex = "a5dcea8d0bba2f1fcfa5824085bf06e65fa1255484dafd499984323672b71fee";
    std::vector<uint8_t> salt = hex_to_bytes(salt_hex);
    const size_t salt_length = salt.size();

    size_t hash_length = 256;
    size_t iterations = 10000;

    size_t result = PQC_pbkdf_2(
        PQC_PBKDF2_HMAC_SHA3, hash_length, password_length, password, master_key_length, master_key, sizeof(master_key),
        salt.data(), salt_length, iterations
    );

    std::vector<uint8_t> expected_key = {0x49, 0xf2, 0x84, 0xe2, 0xfe, 0x15, 0x30, 0x73, 0x60, 0x65, 0x09,
                                         0x7e, 0xf2, 0xc1, 0x18, 0x15, 0xbe, 0xf1, 0x8a, 0x3b, 0xf1, 0xe2,
                                         0xa3, 0x72, 0xb4, 0xce, 0x6d, 0xc5, 0xb6, 0x6f, 0x6e, 0xb6};

    ASSERT_EQ(result, PQC_OK) << "Key derivation failed with error code: " << result;
    ASSERT_EQ(std::vector<uint8_t>(master_key, master_key + master_key_length / 8), expected_key)
        << "Derived key does not match expected key";
}

TEST(PBKDF2, DerivedKeyCorrectnessSHA3_384)
{
    const uint8_t password[] = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
    const size_t password_length = sizeof(password) / sizeof(password[0]);
    const size_t master_key_length = 32 * 8;         // 32 bytes * 8 bits per byte
    uint8_t master_key[master_key_length / 8] = {0}; // Actual byte array

    std::string salt_hex = "a5dcea8d0bba2f1fcfa5824085bf06e65fa1255484dafd499984323672b71fee";
    std::vector<uint8_t> salt = hex_to_bytes(salt_hex);
    const size_t salt_length = salt.size();

    size_t hash_length = 384;
    size_t iterations = 10000;

    size_t result = PQC_pbkdf_2(
        PQC_PBKDF2_HMAC_SHA3, hash_length, password_length, password, master_key_length, master_key, sizeof(master_key),
        salt.data(), salt_length, iterations
    );

    std::vector<uint8_t> expected_key = {0xe8, 0x32, 0x80, 0x7d, 0x8c, 0xeb, 0xbd, 0x09, 0x0f, 0x0e, 0x6b,
                                         0x16, 0x1e, 0xc5, 0xd2, 0x33, 0xf1, 0x80, 0x4e, 0x65, 0xee, 0xb3,
                                         0x73, 0x39, 0xfe, 0xa9, 0xf7, 0xe7, 0x47, 0x69, 0xce, 0x09};

    ASSERT_EQ(result, PQC_OK) << "Key derivation failed with error code: " << result;
    ASSERT_EQ(std::vector<uint8_t>(master_key, master_key + master_key_length / 8), expected_key)
        << "Derived key does not match expected key";
}


TEST(PBKDF2, DerivedKeyCorrectnessSHA3_512)
{
    const uint8_t password[] = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
    const size_t password_length = sizeof(password) / sizeof(password[0]);
    const size_t master_key_length = 32 * 8;         // 32 bytes * 8 bits per byte
    uint8_t master_key[master_key_length / 8] = {0}; // Actual byte array

    std::string salt_hex = "a5dcea8d0bba2f1fcfa5824085bf06e65fa1255484dafd499984323672b71fee";
    std::vector<uint8_t> salt = hex_to_bytes(salt_hex);
    const size_t salt_length = salt.size();

    size_t hash_length = 512;
    size_t iterations = 10000;

    size_t result = PQC_pbkdf_2(
        PQC_PBKDF2_HMAC_SHA3, hash_length, password_length, password, master_key_length, master_key, sizeof(master_key),
        salt.data(), salt_length, iterations
    );

    std::vector<uint8_t> expected_key = {0xcf, 0x40, 0x28, 0x32, 0xad, 0xf5, 0x01, 0x12, 0xc1, 0xbd, 0x0d,
                                         0xbe, 0xf2, 0x0e, 0x96, 0x4b, 0x38, 0xd0, 0x8f, 0x4e, 0x08, 0x43,
                                         0x02, 0xea, 0x5b, 0xd0, 0x43, 0x4c, 0x12, 0x90, 0xbd, 0x6d};

    ASSERT_EQ(result, PQC_OK) << "Key derivation failed with error code: " << result;
    ASSERT_EQ(std::vector<uint8_t>(master_key, master_key + master_key_length / 8), expected_key)
        << "Derived key does not match expected key";
}
