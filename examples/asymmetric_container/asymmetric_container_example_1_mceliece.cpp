#include <cstring>
#include <iostream>
#include <memory>

#include <pqc/container.h>
#include <pqc/mceliece.h>

/*
In this example, we will create a container, put, get a keys from it, and delete the container.
In addition, we will get the size of the container.
*/

int main()
{
    /*
    Creating a asymmetric key container.
    Encryption algorithms can be symmetric and asymmetric. Examples of a
    asymmetric cipher: ntru, mcEliece, dilithium, falcon, kyber, lamport, saber, rainbow.
    The container we are creating is designed for asymmetric
    keys, not suitable for symmetric keys

    This example will use falcone keys. Let's create container
    */

    PQC_CONTAINER_HANDLE new_container = PQC_asymmetric_container_create(PQC_CIPHER_MCELIECE);
    if (new_container == PQC_FAILED_TO_CREATE_CONTAINER)
    {
        std::cout << "\nERROR!!! Failed of container creation!\n";
        return 1;
    }

    /*
    We can get the size of the key container in bytes using the following code.
    Additionally, we will check that the size is not zero.
    */
    size_t size = PQC_asymmetric_container_size(new_container);
    if (size == 0)
    {
        std::cout << "\nERROR!!! Failed container size!\n";
        return 1;
    }

    /*
    This function has second veriant of using. When we have only the cipher type
    without container. We can get size of the container of this type.
    Args:
    cipher type and zero
    */
    size = PQC_asymmetric_container_size_special(PQC_CIPHER_MCELIECE, 0);
    if (size == 0)
    {
        std::cout << "\nERROR!!! Failed container size!\n";
        return 1;
    }

    /*
    So, after creating asymmetric container is empty. There is no control of it.
    Only user should know, is container empty or not. Now let's generate
    falcon keys and put they inside of the container
    */
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
    Now there are public and secret keys inside. We can get them out. Let's do it.
    */
    auto sk_test = std::make_unique<pqc_mceliece_private_key>();
    auto pk_test = std::make_unique<pqc_mceliece_public_key>();
    PQC_asymmetric_container_get_keys(
        PQC_CIPHER_MCELIECE, new_container, pk_test->public_key, sizeof(pk_test->public_key), sk_test->private_key,
        sizeof(sk_test->private_key)
    );

    /*
    keys sould be same with others we had put in. Checking:
    */
    if (memcmp(pub_alice->public_key, pk_test->public_key, sizeof(pub_alice->public_key)) != 0)
    {
        std::cout << "\nERROR!!! Bad public key!\n";
        return 1;
    }
    if (memcmp(priv_alice->private_key, sk_test->private_key, sizeof(priv_alice->private_key)) != 0)
    {
        std::cout << "\nERROR!!! Bad secret key!\n";
        return 1;
    }

    // delete container
    if (PQC_asymmetric_container_close(new_container) != PQC_OK)
    {
        std::cout << "\nERROR!!! Failed to delete container!\n";
        return 1;
    }
    return 0;
}
