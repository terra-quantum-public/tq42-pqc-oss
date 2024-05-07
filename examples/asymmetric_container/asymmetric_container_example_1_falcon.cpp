#include <cstring>
#include <iostream>

#include <pqc/falcon.h>

/*
In this example, we will create a container, put, get a keys from it, and delete the container.
In addition, we will get the size of the container.
*/

int main()
{
    /*
    Creating a asymmetric key container.
    Encryption algorithms can be symmetric and asymmetric. Examples of a
    asymmetric cipher: ntru, falcon, dilithium, falcon, kyber, lamport, saber, rainbow.
    The container we are creating is designed for asymmetric
    keys, not suitable for symmetric keys

    This example will use falcone keys. Let's create container
    */

    PQC_CONTAINER_HANDLE new_container = PQC_asymmetric_container_create(PQC_CIPHER_FALCON);
    if (new_container == PQC_FAILED_TO_CREATE_CONTAINER)
        std::cout << "\nERROR!!! Failed of container creation!\n";

    /*
    We can get the size of the key container in bytes using the following code.
    Additionally, we will check that the size is not zero.
    */
    size_t size = PQC_asymmetric_container_size(new_container);
    if (size == 0)
        std::cout << "\nERROR!!! Failed container size!\n";
    /*
    This function has second veriant of using. When we have only the cipher type
    without container. We can get size of the container of this type.
    Args:
    cipher type and zero
    */
    size = PQC_asymmetric_container_size_special(PQC_CIPHER_FALCON, 0);
    if (size == 0)
        std::cout << "\nERROR!!! Failed container size!\n";

    /*
    So, after creating asymmetric container is empty. There is no control of it.
    Only user should know, is container empty or not. Now let's generate
    falcon keys and put they inside of the container
    */
    pqc_falcon_private_key priv_alice;
    pqc_falcon_public_key pub_alice;
    PQC_generate_key_pair(
        PQC_CIPHER_FALCON, (uint8_t *)&pub_alice, sizeof(pub_alice), (uint8_t *)&priv_alice, sizeof(priv_alice)
    );


    PQC_asymmetric_container_put_keys(
        PQC_CIPHER_FALCON, new_container, (uint8_t *)&pub_alice, sizeof(pub_alice), (uint8_t *)&priv_alice,
        sizeof(priv_alice)
    );

    /*
    Now there are public and secret keys inside. We can get them out. Let's do it.
    */
    pqc_falcon_private_key sk_test;
    pqc_falcon_public_key pk_test;

    PQC_asymmetric_container_get_keys(
        PQC_CIPHER_FALCON, new_container, (uint8_t *)&pk_test, sizeof(pk_test), (uint8_t *)&sk_test, sizeof(sk_test)
    );


    /*
    keys sould be same with others we had put in. Checking:
    */
    if (memcmp((uint8_t *)&pub_alice, (uint8_t *)&pk_test, sizeof(pub_alice)) != 0)
    {
        std::cout << "\nERROR!!! Bad public key!\n";
    }
    if (memcmp((uint8_t *)&priv_alice, (uint8_t *)&sk_test, sizeof(priv_alice)) != 0)
    {
        std::cout << "\nERROR!!! Bad secret key!\n";
    }


    // delete container
    if (PQC_asymmetric_container_close(new_container) != PQC_OK)
    {
        std::cout << "\nERROR!!! Failed to delete container!\n";
    }
    return 0;
}
