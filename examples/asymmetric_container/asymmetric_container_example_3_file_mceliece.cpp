#include <cstring>
#include <iostream>
#include <memory>

#include <pqc/container.h>
#include <pqc/mceliece.h>

/*
In this example, we will write the container to a file and extract the record from the file.
*/

int main()
{
    /*
    Creating a asymmetric key container. Generate and put key inside. Cipher FALCON.
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
    Now let's try to save the container to a file.
    */
    size_t result = PQC_asymmetric_container_save_as(
        PQC_CIPHER_MCELIECE, new_container, "some-unique-container-name-mceliece.pqc", "password", "salt"
    );
    if (result != PQC_OK)
    {
        std::cout << "\nERROR!!! Failed of file creation\n";
        return 1;
    }

    /*
    Let's create new container, get kes from file and compare with old keys
    */
    PQC_CONTAINER_HANDLE resultContainer = PQC_asymmetric_container_open(
        PQC_CIPHER_MCELIECE, "some-unique-container-name-mceliece.pqc", "password", "salt"
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
        std::cout << "\nERROR!!! Failed of keys reading\n";
        return 1;
    }

    if (memcmp(pub_alice->public_key, pk_test->public_key, sizeof(pub_alice->public_key)) != 0 ||
        memcmp(priv_alice->private_key, sk_test->private_key, sizeof(priv_alice->private_key)) != 0)
    {
        std::cout << "\nERROR!!! Keys are not equal!!!\n";
        return 1;
    }

    PQC_asymmetric_container_close(new_container);
    PQC_asymmetric_container_close(resultContainer);

    return 0;
}
