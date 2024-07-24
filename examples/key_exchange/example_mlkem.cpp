#include <cstring>
#include <iostream>

#include <pqc/aes.h>
#include <pqc/ml-kem.h>

/*
Example of Key exchange mechanism using asymmetric encryption.
Algorythms KYBER, ML-KEM, McEliece are used similarly.
Alice and Bob create their key pairs. Public keys and encoded message are shared
Message is encoded  and shared from Alice to Bob with PQC_kem_encode_secret
Message is decoded by Bob with PQC_kem_decode_secret


This example for ML-KEM system
*/

int main()
{
    // Bob's private and public keys
    pqc_ml_kem_private_key priv_bob;
    pqc_ml_kem_public_key pub_bob;

    // buffers to store shared info (PQC_ML_KEM_SHARED_LENGTH == PQC_AES_KEYLEN == 32 bytes)
    uint8_t shared_alice[PQC_ML_KEM_SHARED_LENGTH], shared_bob[PQC_ML_KEM_SHARED_LENGTH];

    pqc_ml_kem_message message;

    const size_t info_size = 10;
    // party_a_info (in): additional data to be used for key derivation
    uint8_t party_a_info[info_size] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};

    size_t key_pair = PQC_generate_key_pair(
        PQC_CIPHER_ML_KEM, (uint8_t *)&pub_bob, sizeof(pub_bob), (uint8_t *)&priv_bob, sizeof(priv_bob)
    );
    if (key_pair != PQC_OK)
        std::cout << "ERROR!!! Key pair hasn't been successfully created" << std::endl;

    // context of algorithm object
    CIPHER_HANDLE bob = PQC_init_context(PQC_CIPHER_ML_KEM, (uint8_t *)&priv_bob, sizeof(priv_bob));
    if (bob == PQC_BAD_CIPHER)
        std::cout << "ERROR!!! During context creation: Unknown/unsupported cipher" << std::endl;

    // To derive shared key to be used for data encryption and message for other party call
    size_t encode = PQC_kem_encode(
        PQC_CIPHER_ML_KEM, (uint8_t *)&message, sizeof(message), party_a_info, info_size, (uint8_t *)&pub_bob,
        sizeof(pub_bob), (uint8_t *)&shared_alice, sizeof(shared_alice)
    );

    // encode should be equal to PQC_OK
    if (encode != PQC_OK)
        std::cout << "ERROR!!! Secret hasn't been successfully encoding" << std::endl;

    //(Bob) To derive shared key from message and private key
    size_t decode = PQC_kem_decode(
        bob, (uint8_t *)&message, sizeof(message), party_a_info, info_size, (uint8_t *)&shared_bob, sizeof(shared_alice)
    );

    // decode shoul be equal to PQC_OK
    if (decode != PQC_OK)
        std::cout << "ERROR!!! Secret hasn't been successfully decoded" << std::endl;

    // Decoded message on the Bob's side should be equal to the message shared by Alice
    //(PQC_ML_KEM_SHARED_LENGTH == PQC_AES_KEYLEN == 32 bytes)

    if (memcmp(shared_bob, shared_alice, PQC_AES_KEYLEN) != 0)
        std::cout << "ERROR!!! Messages are not equal" << std::endl;

    PQC_close_context(bob);

    return 0;
}
