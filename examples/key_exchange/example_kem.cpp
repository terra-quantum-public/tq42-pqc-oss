#include <cstring>
#include <iostream>
#include <vector>

#include <pqc/common.h>
// Include header for appropriate key exchange algorithm:
// #include <pqc/kyber.h> for Kyber
// #include <pqc/mceliece.h> for McEliece
// #include <pqc/ml-kem.h> for ML-KEM
#include <pqc/ml-kem.h>

/*
Example of Key exchange mechanism using asymmetric encryption.
Alice and Bob create their key pairs. Public keys and encoded message are shared
Message is encoded  and shared from Alice to Bob with PQC_kem_encapsulate_secret
Message is decoded by Bob with PQC_kem_decapsulate_secret
*/

int main()
{
    // Select appropriate cipher
    const uint32_t cipher = PQC_CIPHER_ML_KEM_1024;
    const size_t pk_len = PQC_cipher_get_length(cipher, PQC_LENGTH_PUBLIC);
    const size_t ss_len = PQC_cipher_get_length(cipher, PQC_LENGTH_SHARED);
    const size_t msg_len = PQC_cipher_get_length(cipher, PQC_LENGTH_MESSAGE);
    std::vector<uint8_t> pk(pk_len);       // public (encapsulation) key
    std::vector<uint8_t> ss_alice(ss_len); // shared secret (Alice)
    std::vector<uint8_t> ss_bob(ss_len);   // shared secret (Bob)
    std::vector<uint8_t> msg(msg_len);     // message from Alice to Bob

    // Context init for Bob
    CIPHER_HANDLE bob = PQC_context_init_asymmetric(cipher, nullptr, 0, nullptr, 0);
    if (bob == PQC_BAD_CIPHER)
    {
        std::cout << "Context init for Bob failed!" << std::endl;
        return -1;
    }

    // Bob generates public (encapsulation) key (to share with Alice) and secure (decapsulation) key
    size_t gen_keypair_result = PQC_context_keypair_generate(bob);
    if (gen_keypair_result != PQC_OK)
    {
        std::cout << "Key generation failed!" << std::endl;
        return -1;
    }

    // Get public (encapsulation) key to share it with Alice
    size_t pk_get_result = PQC_context_get_public_key(bob, pk.data(), pk.size());
    if (pk_get_result != PQC_OK)
    {
        std::cout << "Public key getting error!" << std::endl;
        return -1;
    }

    // Context init for Alice
    CIPHER_HANDLE alice = PQC_context_init_asymmetric(cipher, pk.data(), pk.size(), nullptr, 0);
    if (alice == PQC_BAD_CIPHER)
    {
        std::cout << "Context init for Alice failed!" << std::endl;
        return -1;
    }

    // Alice derives shared key to be used for data encryption and message for other party call
    size_t enc_result = PQC_kem_encapsulate_secret(alice, msg.data(), msg.size(), ss_alice.data(), ss_alice.size());
    if (enc_result != PQC_OK)
    {
        std::cout << "Secret hasn't been successfully encapsulated!" << std::endl;
        return -1;
    }

    // Bob derives shared key from message and private key
    size_t dec_result = PQC_kem_decapsulate_secret(bob, msg.data(), msg.size(), ss_bob.data(), ss_bob.size());
    if (dec_result != PQC_OK)
    {
        std::cout << "Secret hasn't been successfully decapsulated!" << std::endl;
        return -1;
    }

    if (ss_bob == ss_alice)
        std::cout << "Shared secrets are equal!" << std::endl;
    else
        std::cout << "Error! Shared secrets are not equal!" << std::endl;

    // Encapsulation / decapsulation with party info

    std::fill(ss_alice.begin(), ss_alice.end(), (uint8_t)0); // clear
    std::fill(ss_bob.begin(), ss_bob.end(), (uint8_t)1);     // clear

    const size_t info_size = 10;
    // party_a_info (in): additional data to be used for key derivation
    uint8_t party_a_info[info_size] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};

    enc_result =
        PQC_kem_encapsulate(alice, msg.data(), msg.size(), party_a_info, info_size, ss_alice.data(), ss_alice.size());
    if (enc_result != PQC_OK)
    {
        std::cout << "Secret hasn't been successfully encapsulated using party info!" << std::endl;
        return -1;
    }

    dec_result =
        PQC_kem_decapsulate(bob, msg.data(), msg.size(), party_a_info, info_size, ss_bob.data(), ss_bob.size());
    if (dec_result != PQC_OK)
    {
        std::cout << "Secret hasn't been successfully decapsulated using party info!" << std::endl;
        return -1;
    }

    if (ss_bob == ss_alice)
        std::cout << "Shared secrets are equal!" << std::endl;
    else
        std::cout << "Error! Shared secrets are not equal!" << std::endl;

    PQC_context_close(alice);
    PQC_context_close(bob);

    return 0;
}
