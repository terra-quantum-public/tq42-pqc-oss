#include <iostream>
#include <vector>

#include <pqc/common.h>

// Include header for appropriate signature algorithm:
// #include <pqc/dilithium.h> for Dilithium
// #include <pqc/falcon.h> for Falcon
// #include <pqc/ml-dsa.h> for ML-DSA
// #include <pqc/slh-dsa.h> for SLH-DSA
#include <pqc/slh-dsa.h>

int main()
{
    // Select appropriate cipher
    const uint32_t cipher = PQC_CIPHER_SLH_DSA_SHAKE_256F;
    const size_t pk_len = PQC_cipher_get_length(cipher, PQC_LENGTH_PUBLIC);
    const size_t sk_len = PQC_cipher_get_length(cipher, PQC_LENGTH_PRIVATE);
    const size_t sig_len = PQC_cipher_get_length(cipher, PQC_LENGTH_SIGNATURE);
    std::vector<uint8_t> pk(pk_len);
    std::vector<uint8_t> sk(sk_len);
    std::vector<uint8_t> sig(sig_len);

    // Init context for Alice
    CIPHER_HANDLE context_alice = PQC_context_init_asymmetric(cipher, nullptr, 0, nullptr, 0);
    if (context_alice == PQC_BAD_CIPHER)
    {
        std::cout << "Failed to initialize cryptographic context for Alice!" << std::endl;
        return -1;
    }

    // Generate a key pair for Alice
    size_t gen_keypair_result = PQC_context_keypair_generate(context_alice);
    if (gen_keypair_result != PQC_OK)
    {
        std::cout << "Key generation failed!" << std::endl;
        return -1;
    }

    // Extract public key to share it with Bob
    size_t pk_get_result = PQC_context_get_public_key(context_alice, pk.data(), pk.size());
    if (pk_get_result != PQC_OK)
    {
        std::cout << "Public key getting failed!" << std::endl;
        return -1;
    }

    // Define a message that will be signed
    char message[] = "Here is my message I will sign by signature algorithm!";

    // Sign the message using Alice's context
    size_t sign_result =
        PQC_signature_create(context_alice, (uint8_t *)message, sizeof(message), sig.data(), sig.size());
    if (sign_result != PQC_OK)
    {
        std::cout << "Signing process failed!" << std::endl;
        return -1;
    }
    PQC_context_close(context_alice);

    // Init context for Bob using Alice's public key
    CIPHER_HANDLE context_bob = PQC_context_init_asymmetric(cipher, pk.data(), pk.size(), nullptr, 0);
    if (context_bob == PQC_BAD_CIPHER)
    {
        std::cout << "Failed to initialize cryptographic context for Bob!" << std::endl;
        return -1;
    }

    // Bob attempts to verify the signature of the signed message
    size_t verify_result =
        PQC_signature_verify(context_bob, (uint8_t *)message, sizeof(message), sig.data(), sig.size());
    if (verify_result == PQC_OK)
    {
        std::cout << "Signature is valid!" << std::endl;
    }
    else
    {
        std::cout << "Signature verification failed!" << std::endl;
    }

    return 0;
}
