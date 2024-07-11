#include <iostream>

#include <cstring>

#include <pqc/aes.h>

// parties can obtain a common key through asymmetric key exchange

// OFB

// OFB  takes a fixed length iv, fixed-length key and
// fixed-length plaintext. Plaintext size MUST be mutile of AES_BLOCKLEN;
// Decryption works in the same way

// Party A encrypts its plaintext using a key and iv. Then data, its length, key and iv must be
// transmitted to party B


void ofb_encrypt(uint8_t key[], uint8_t data[], const int data_len, uint8_t iv[])
{
    CIPHER_HANDLE context;

    context = PQC_init_context_iv(PQC_CIPHER_AES, key, PQC_AES_KEYLEN, iv, PQC_AES_IVLEN);
    PQC_encrypt(context, PQC_AES_M_OFB, data, data_len);

    PQC_close_context(context);
}

// Party B decrypts the ciphertext using the same key and iv.

void ofb_decrypt(uint8_t key[], uint8_t data[], const int data_len, uint8_t iv[])
{
    CIPHER_HANDLE context;
    context = PQC_init_context_iv(PQC_CIPHER_AES, key, PQC_AES_KEYLEN, iv, PQC_AES_IVLEN);

    PQC_decrypt(context, PQC_AES_M_OFB, data, data_len);

    PQC_close_context(context);
}


int main()
{
    // OFB
    uint8_t key[PQC_AES_KEYLEN] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 11,  12,  13,  14,  15, 16,
                                   17,  18,  19,  20,  '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 31, 32};

    const int data_len = PQC_AES_BLOCKLEN * 2;

    uint8_t data_a[data_len] = {24, 76, 85, 125, 230, 234, 78, 42, 58, 39, 11, 9, 7, 12, 18, 74};
    uint8_t data_original[data_len] = {0};
    uint8_t data_b[data_len] = {0};

    memcpy(data_original, data_a, sizeof(data_a)); // Copy of original data for verification.

    uint8_t iv[PQC_AES_IVLEN] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

    ofb_encrypt(key, data_a, data_len, iv); // This happens at party A

    memcpy(data_b, data_a, data_len); // Emulate transfer of encrypted message to party B

    ofb_decrypt(key, data_b, data_len, iv); // This happens at party B

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
