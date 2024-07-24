#include <iostream>
#include <vector>

#include <pqc/common.h>
#include <pqc/ml-dsa.h>

// Macros simplify the creation of byte vectors for ML-DSA private and public keys
#define ML_DSA_PRIVATE_KEY(x) std::vector<uint8_t> x(sizeof(pqc_ml_dsa_private_key))
#define ML_DSA_PUBLIC_KEY(x) std::vector<uint8_t> x(sizeof(pqc_ml_dsa_public_key))
#define ML_DSA_SIGNATURE(x) std::vector<uint8_t> x(sizeof(pqc_ml_dsa_signature))

int main()
{
    ML_DSA_PRIVATE_KEY(priv_alice);
    ML_DSA_PUBLIC_KEY(pub_alice);
    ML_DSA_SIGNATURE(signature);

    // Generate a ML-DSA key pair for Alice
    size_t generateResult = PQC_generate_key_pair(
        PQC_CIPHER_ML_DSA, pub_alice.data(), pub_alice.size(), priv_alice.data(), priv_alice.size()
    );

    // Check if key generation was successful
    if (generateResult != PQC_OK)
    {
        std::cout << "Key generation failed!" << std::endl;
    }

    CIPHER_HANDLE ML_DSA_ContextAlice = PQC_init_context(PQC_CIPHER_ML_DSA, priv_alice.data(), priv_alice.size());
    if (ML_DSA_ContextAlice == PQC_BAD_CIPHER)
    {
        std::cout << "Failed to initialize cryptographic context!" << std::endl;
    }

    // Define a message that will be signed using ML-DSA signature algorithm
    char message[] = "Here is my message I will sign by ML-DSA signature algorithm!";

    // Sign the message with ML-DSA algorithm using Alice's context
    size_t signResult =
        PQC_sign(ML_DSA_ContextAlice, (uint8_t *)message, sizeof(message), signature.data(), signature.size());

    // Check if the signing process was successful
    if (signResult != PQC_OK)
    {
        std::cout << "Signing process failed!" << std::endl;
    }

    // Attempt to verify the signature of the signed message using Alice's public key
    size_t verifyResult = PQC_verify(
        PQC_CIPHER_ML_DSA, pub_alice.data(), pub_alice.size(), (uint8_t *)message, sizeof(message), signature.data(),
        signature.size()
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
