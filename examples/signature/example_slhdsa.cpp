#include <iostream>
#include <vector>

#include <pqc/common.h>
#include <pqc/slh-dsa.h>

// Macros simplify the creation of byte vectors for SLH-DSA private and public keys
#define SLH_DSA_PRIVATE_KEY(x) std::vector<uint8_t> x(sizeof(pqc_slh_dsa_private_key))
#define SLH_DSA_PUBLIC_KEY(x) std::vector<uint8_t> x(sizeof(pqc_slh_dsa_public_key))
#define SLH_DSA_SIGNATURE(x) std::vector<uint8_t> x(sizeof(pqc_slh_dsa_signature))

int main()
{
    SLH_DSA_PRIVATE_KEY(priv_alice);
    SLH_DSA_PUBLIC_KEY(pub_alice);
    SLH_DSA_SIGNATURE(signature);

    // Generate a SLH-DSA key pair for Alice
    size_t generateResult = PQC_generate_key_pair(
        PQC_CIPHER_SLH_DSA_SHAKE_256F, pub_alice.data(), pub_alice.size(), priv_alice.data(), priv_alice.size()
    );

    // Check if key generation was successful
    if (generateResult != PQC_OK)
    {
        std::cout << "Key generation failed!" << std::endl;
    }

    CIPHER_HANDLE SLH_DSA_ContextAlice =
        PQC_init_context(PQC_CIPHER_SLH_DSA_SHAKE_256F, priv_alice.data(), priv_alice.size());
    if (SLH_DSA_ContextAlice == PQC_BAD_CIPHER)
    {
        std::cout << "Failed to initialize cryptographic context!" << std::endl;
    }

    // Define a message that will be signed using SLH-DSA signature algorithm
    char message[] = "Here is my message I will sign by SLH-DSA signature algorithm!";

    // Sign the message with SLH-DSA algorithm using Alice's context
    size_t signResult =
        PQC_sign(SLH_DSA_ContextAlice, (uint8_t *)message, sizeof(message), signature.data(), signature.size());

    // Check if the signing process was successful
    if (signResult != PQC_OK)
    {
        std::cout << "Signing process failed!" << std::endl;
    }

    // Attempt to verify the signature of the signed message using Alice's public key
    size_t verifyResult = PQC_verify(
        PQC_CIPHER_SLH_DSA_SHAKE_256F, pub_alice.data(), pub_alice.size(), (uint8_t *)message, sizeof(message),
        signature.data(), signature.size()
    );

    // Check the result of the signature verification
    if (verifyResult == PQC_OK)
    {
        std::cout << "Signature is valid!" << std::endl;
    }
    else
    {
        std::cout << "Signature verification failed!" << std::endl;
    }

    return 0;
}
