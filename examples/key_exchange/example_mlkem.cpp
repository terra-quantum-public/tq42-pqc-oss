#include <iostream>
#include <vector>

#include <pqc/common.h>
#include <pqc/ml-kem.h>

/*
Example of Key exchange mechanism using asymmetric encryption.
Algorythms KYBER, ML-KEM, McEliece are used similarly.
Alice and Bob create their key pairs. Public keys and encoded message are shared
Message is encoded  and shared from Alice to Bob with PQC_kem_encapsulate_secret
Message is decoded by Bob with PQC_kem_decapsulate_secret


This example for ML-KEM system
*/

int main()
{
    const uint32_t cipher = PQC_CIPHER_ML_KEM_1024;
    const size_t pk_len = PQC_cipher_get_length(cipher, PQC_LENGTH_PUBLIC);
    const size_t sk_len = PQC_cipher_get_length(cipher, PQC_LENGTH_PRIVATE);
    const size_t ss_len = PQC_cipher_get_length(cipher, PQC_LENGTH_SHARED);
    const size_t msg_len = PQC_cipher_get_length(cipher, PQC_LENGTH_MESSAGE);
    std::vector<uint8_t> pk(pk_len);       // public (encapsulation) key
    std::vector<uint8_t> sk(sk_len);       // secure (decapsultaion) key
    std::vector<uint8_t> ss_alice(ss_len); // shared secret (Alice)
    std::vector<uint8_t> ss_bob(ss_len);   // shared secret (Bob)
    std::vector<uint8_t> msg(msg_len);     // message from Alice to Bob

    const size_t info_size = 10;
    // party_a_info (in): additional data to be used for key derivation
    uint8_t party_a_info[info_size] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};

    // Bob generates public (encapsulation) key (to share with Alice) and secure (decapsulation) key
    size_t gen_result = PQC_keypair_generate(cipher, pk.data(), pk.size(), sk.data(), sk.size());
    if (gen_result != PQC_OK)
        std::cout << "Key generation failed!" << std::endl;

    // Alice derives shared secret and message using encapsulation key from Bob
    size_t enc_result = PQC_kem_encapsulate(
        cipher, msg.data(), msg.size(), party_a_info, info_size, pk.data(), pk.size(), ss_alice.data(), ss_alice.size()
    );
    if (enc_result != PQC_OK)
        std::cout << "Encapsulation failed!" << std::endl;

    // Bob inits context for decapsulation shared secret from Alice's message using his decapsulation key
    CIPHER_HANDLE bob_ctx = PQC_context_init(cipher, sk.data(), sk.size());
    if (bob_ctx == PQC_BAD_CIPHER)
        std::cout << "Failed to initialize cryptographic context!" << std::endl;
    size_t dec_result =
        PQC_kem_decapsulate(bob_ctx, msg.data(), msg.size(), party_a_info, info_size, ss_bob.data(), ss_bob.size());
    if (dec_result != PQC_OK)
        std::cout << "Decapsulation failed!" << std::endl;

    if (ss_bob == ss_alice)
        std::cout << "Shared secrets are equal!" << std::endl;
    else
        std::cout << "Error! Shared secrets are not equal!" << std::endl;

    PQC_context_close(bob_ctx);

    return 0;
}
