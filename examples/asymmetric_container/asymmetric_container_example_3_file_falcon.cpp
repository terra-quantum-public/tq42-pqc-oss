#include <cstring>
#include <iostream>

#include <pqc/container.h>
#include <pqc/falcon.h>

/*
In this example, we will write the container to a file and extract the record from the file.
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
    Now let's try to save the container to a file.
    */
    size_t result = PQC_asymmetric_container_save_as(
        PQC_CIPHER_FALCON, new_container, "some-unique-container-name-falcon.pqc", "password", "salt"
    );
    if (result != PQC_OK)
    {
        std::cout << "\nFailed of file creation\n";
    }

    /*
    Let's create new container, get keys from file and compare with old keys
    */
    PQC_CONTAINER_HANDLE resultContainer =
        PQC_asymmetric_container_open(PQC_CIPHER_FALCON, "some-unique-container-name-falcon.pqc", "password", "salt");
    if (resultContainer == PQC_FAILED_TO_CREATE_CONTAINER)
        std::cout << "\nERROR!!! Failed of container creation!\n";

    pqc_falcon_private_key sk_test;
    pqc_falcon_public_key pk_test;

    result = PQC_asymmetric_container_get_keys(
        PQC_CIPHER_FALCON, resultContainer, (uint8_t *)&pk_test, sizeof(pk_test), (uint8_t *)&sk_test, sizeof(sk_test)
    );
    if (result != PQC_OK)
    {
        std::cout << "\nFailed of keys reading\n";
    }

    if (memcmp((uint8_t *)&pub_alice, (uint8_t *)&pk_test, sizeof(pub_alice)) != 0 ||
        memcmp((uint8_t *)&priv_alice, (uint8_t *)&sk_test, sizeof(priv_alice)) != 0)
    {
        std::cout << "\nERROR!!! Keys are not equal!!!\n";
    }

    PQC_asymmetric_container_close(new_container);
    PQC_asymmetric_container_close(resultContainer);

    return 0;
}
