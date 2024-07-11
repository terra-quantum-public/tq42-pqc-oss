#include <cstring>
#include <iostream>

#include <pqc/aes.h>

// CBC

// parties can obtain a common key through asymmetric key exchange

// CBC takes a fixed-length iv, fixed-length key and
// fixed-length plaintext. Plaintext size MUST be mutile of AES_BLOCKLEN;

// Party A encrypts its plaintext using a key and iv. Then data, its length, key and iv must be
// transmitted to party B

void cbc_encrypt(uint8_t key[], uint8_t data[], const int data_len, uint8_t iv[])
{
    CIPHER_HANDLE context;

    context = PQC_init_context_iv(PQC_CIPHER_AES, key, PQC_AES_KEYLEN, iv, PQC_AES_IVLEN);

    PQC_encrypt(context, PQC_AES_M_CBC, data, data_len);

    PQC_close_context(context);
}

// Party B decrypts the ciphertext using the same key and iv.

void cbc_decrypt(uint8_t key[], uint8_t data[], const int data_len, uint8_t iv[])
{
    CIPHER_HANDLE context;

    context = PQC_init_context_iv(PQC_CIPHER_AES, key, PQC_AES_KEYLEN, iv, PQC_AES_IVLEN);

    PQC_decrypt(context, PQC_AES_M_CBC, data, data_len);

    PQC_close_context(context);
}


int main()
{
    // CBC

    uint8_t key[PQC_AES_KEYLEN] = {1,   2,   3,   4,   5,  6,  7,  8,  9,  10, '1', '2', '3', '4', '5', '6',
                                   '7', '8', '9', '0', 21, 22, 23, 24, 25, 26, 27,  28,  29,  30,  'A', 'B'};

    const int data_len = PQC_AES_BLOCKLEN * 2;


    uint8_t data_a[data_len] = {88, 16, 49, 23, 78, 30, 17, 99, 253, 164, 82, 97, 188, 87, 61, 13};
    uint8_t data_original[data_len] = {0};
    uint8_t data_b[data_len] = {0};

    uint8_t iv[PQC_AES_IVLEN] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

    memcpy(data_original, data_a, sizeof(data_a)); // Copy of original data for verification.

    cbc_encrypt(key, data_a, data_len, iv); // This happens at party A

    memcpy(data_b, data_a, data_len); // Emulate transfer of encrypted message to party B

    cbc_decrypt(key, data_b, data_len, iv); // This happens at party B

    if (memcmp(data_b, data_original, data_len) == 0) // Verification
    {
        std::cout << "Verification successful." << std::endl;
    }
    else
    {
        std::cout << "Verification failed." << std::endl;
    }

    return 0;
}
