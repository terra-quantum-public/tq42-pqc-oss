#include <cstring>
#include <iostream>
#include <memory>

#include <pqc/aes.h>
#include <pqc/container.h>
#include <pqc/mceliece.h>

/*
In this example, we will create container, transform it into a special string of bytes,
transform it back.
*/

int main()
{
    /*
    Creating a asymmetric key container. Generate and put key inside. Cipher MCELIECE.
    */

    PQC_CONTAINER_HANDLE new_container = PQC_asymmetric_container_create(PQC_CIPHER_MCELIECE);
    if (new_container == PQC_FAILED_TO_CREATE_CONTAINER)
    {
        std::cout << "\nERROR!!! Failed of container creation!\n";
        return 1;
    }

    auto priv_alice = std::make_unique<pqc_mceliece_private_key>();
    auto pub_alice = std::make_unique<pqc_mceliece_public_key>();
    PQC_keypair_generate(
        PQC_CIPHER_MCELIECE, pub_alice->public_key, sizeof(pub_alice->public_key), priv_alice->private_key,
        sizeof(priv_alice->private_key)
    );

    PQC_asymmetric_container_put_keys(
        PQC_CIPHER_MCELIECE, new_container, pub_alice->public_key, sizeof(pub_alice->public_key),
        priv_alice->private_key, sizeof(priv_alice->private_key)
    );

    /*
    We can transform container to the encrypted byte string. Let's do it
    */
    uint8_t * container_data = new uint8_t[PQC_asymmetric_container_size(new_container)];

    // aes will use for string encryption
    uint8_t creation_key[PQC_AES_KEYLEN] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6,
                                            7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2};
    uint8_t creation_iv[PQC_AES_IVLEN] = {9, 8, 7, 6, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6};

    size_t result = PQC_asymmetric_container_get_data(
        new_container, container_data, PQC_asymmetric_container_size(new_container), creation_key, PQC_AES_KEYLEN,
        creation_iv, PQC_AES_IVLEN
    );
    if (result != PQC_OK)
    {
        std::cout << "\nFailed of string transforming\n";
        return 1;
    }

    /*
    Let's restore container from string. The keys inside should be equal with others we generated before
    */
    PQC_CONTAINER_HANDLE resultContainer = PQC_asymmetric_container_from_data(
        PQC_CIPHER_MCELIECE, container_data, PQC_asymmetric_container_size(new_container), creation_key, PQC_AES_KEYLEN,
        creation_iv, PQC_AES_IVLEN
    );
    if (resultContainer == PQC_FAILED_TO_CREATE_CONTAINER)
    {
        std::cout << "\nERROR!!! Failed of container creation!\n";
        return 1;
    }

    auto sk_test = std::make_unique<pqc_mceliece_private_key>();
    auto pk_test = std::make_unique<pqc_mceliece_public_key>();
    result = PQC_asymmetric_container_get_keys(
        PQC_CIPHER_MCELIECE, resultContainer, pk_test->public_key, sizeof(pk_test->public_key), sk_test->private_key,
        sizeof(sk_test->private_key)
    );
    if (result != PQC_OK)
    {
        std::cout << "\nERROR!!! Failed of container creation!\n";
        return 1;
    }

    if (memcmp(pub_alice->public_key, pk_test->public_key, sizeof(pub_alice->public_key)) != 0 ||
        memcmp(priv_alice->private_key, sk_test->private_key, sizeof(priv_alice->private_key)) != 0)
    {
        std::cout << "\nERROR!!! Keys are not equal!!!\n";
        return 1;
    }

    delete[] container_data;

    PQC_asymmetric_container_close(new_container);
    PQC_asymmetric_container_close(resultContainer);

    return 0;
}
