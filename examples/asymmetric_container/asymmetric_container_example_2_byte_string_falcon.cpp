#include <cstring>
#include <iostream>

#include <pqc/aes.h>
#include <pqc/container.h>
#include <pqc/falcon.h>

/*
In this example, we will create container, transform it into a special string of bytes,
transform it back.
*/

int main()
{
    /*
    Creating a asymmetric key container. Generate and put key inside. Cipher FALCON.
    */

    PQC_CONTAINER_HANDLE new_container = PQC_asymmetric_container_create(PQC_CIPHER_FALCON);
    if (new_container == PQC_FAILED_TO_CREATE_CONTAINER)
        std::cout << "\nERROR!!! Failed of container creation!\n";

    pqc_falcon_private_key priv_alice;
    pqc_falcon_public_key pub_alice;
    PQC_keypair_generate(
        PQC_CIPHER_FALCON, (uint8_t *)&pub_alice, sizeof(pub_alice), (uint8_t *)&priv_alice, sizeof(priv_alice)
    );

    PQC_asymmetric_container_put_keys(
        PQC_CIPHER_FALCON, new_container, (uint8_t *)&pub_alice, sizeof(pub_alice), (uint8_t *)&priv_alice,
        sizeof(priv_alice)
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
    }

    /*
    Let;s restore container from string. The keys inside should be equal with others we generated before
    */

    PQC_CONTAINER_HANDLE resultContainer = PQC_asymmetric_container_from_data(
        PQC_CIPHER_FALCON, container_data, PQC_asymmetric_container_size(new_container), creation_key, PQC_AES_KEYLEN,
        creation_iv, PQC_AES_IVLEN
    );
    if (resultContainer == PQC_FAILED_TO_CREATE_CONTAINER)
    {
        std::cout << "\nERROR!!! Failed of container creation!\n";
    }

    pqc_falcon_private_key sk_test;
    pqc_falcon_public_key pk_test;

    result = PQC_asymmetric_container_get_keys(
        PQC_CIPHER_FALCON, resultContainer, (uint8_t *)&pk_test, sizeof(pk_test), (uint8_t *)&sk_test, sizeof(sk_test)
    );
    if (result != PQC_OK)
    {
        std::cout << "\nERROR!!! Failed of container creation!\n";
    }

    if (memcmp((uint8_t *)&pub_alice, (uint8_t *)&pk_test, sizeof(pub_alice)) != 0 ||
        memcmp((uint8_t *)&priv_alice, (uint8_t *)&sk_test, sizeof(priv_alice)) != 0)
    {
        std::cout << "\nERROR!!! Keys are not equal!!!\n";
    }

    delete[] container_data;

    PQC_asymmetric_container_close(new_container);
    PQC_asymmetric_container_close(resultContainer);

    return 0;
}
