#include <cstring>
#include <iostream>
#include <vector>

#include <pqc/aes.h>

// parties can obtain a common key through asymmetric key exchange

// Party A encrypts its plaintext using a key. Then data, its length, and key must be
// transmitted to party B

void gcm_encrypt(
    const std::vector<uint8_t> & key, std::vector<uint8_t> & data, const std::vector<uint8_t> & aad,
    std::vector<uint8_t> & tag
)
{
    CIPHER_HANDLE context;

    context = PQC_context_init(PQC_CIPHER_AES, key.data(), PQC_AES_KEYLEN);
    PQC_aead_encrypt(
        context, PQC_AES_M_CTR, data.data(), data.size(), aad.data(), aad.size(), tag.data(), PQC_AES_IVLEN
    );
}


// Party B decrypts the ciphertext using the same key.

void gcm_decrypt(
    const std::vector<uint8_t> & key, std::vector<uint8_t> data, std::vector<uint8_t> aad,
    const std::vector<uint8_t> tag
)
{
    CIPHER_HANDLE context;

    context = PQC_context_init(PQC_CIPHER_AES, key.data(), PQC_AES_KEYLEN);
    PQC_aead_decrypt(
        context, PQC_AES_M_CTR, data.data(), data.size(), aad.data(), aad.size(), tag.data(), PQC_AES_IVLEN
    );

    PQC_context_close(context);
}


int main()
{
    // CTR
    std::vector<uint8_t> key = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'A', 'B', 'C', 'D', 'E', 'F',
                                'G', 'H', 'I', 'J', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'K', 'L'};

    const int data_len = PQC_AES_BLOCKLEN;
    std::vector<uint8_t> data_a = {89, 234, 87, 91, 40, 83, 179, 255, 80, 66, 19, 45, 89, 0, 64, 123};
    std::vector<uint8_t> data_original(data_a);
    std::vector<uint8_t> data_b(data_len);
    std::vector<uint8_t> aad = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20};
    std::vector<uint8_t> tag(PQC_AES_IVLEN);

    gcm_encrypt(key, data_a, aad, tag); // This happens at party A

    data_b = data_a; // Emulate transfer of encrypted message to party B

    gcm_decrypt(key, data_b, aad, tag); // This happens at party B

    if (data_b == data_original) // Vrification
    {
        std::cout << "Verification successful." << std::endl;
    }
    else
    {
        std::cout << "Verification failed." << std::endl;
    }

    return 0;
}
