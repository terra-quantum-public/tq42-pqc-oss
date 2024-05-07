#include <iostream>

#include <pqc/aes.h>

/*
In this example, we will create a container, get a key from it, and delete the container.
In addition, we will get the size of the container.
*/

int main()
{
    /*
    Creating a symmetric key container.
    Encryption algorithms can be symmetric and asymmetric. Example of a
    symmetric cipher: aes. The container we are creating is designed for symmetric
    keys, not suitable for asymmetric keys
    */
    uint8_t testKey1[PQC_AES_KEYLEN] = {0};
    PQC_CONTAINER_HANDLE new_container = PQC_symmetric_container_create();

    if (new_container == PQC_FAILED_TO_CREATE_CONTAINER)
        std::cout << "\nERROR!!! Failed of container creation!\n";

    /*
    We can get the size of the key container in bytes using the following code.
    Additionally, we will check that the size is not zero.
    */
    const size_t size = PQC_symmetric_container_size(new_container);
    if (size == 0)
        std::cout << "\nERROR!!! Failed container size!\n";

    if (PQC_symmetric_container_get_key(
            new_container, 0, 100, PQC_CIPHER_AES, PQC_AES_M_ECB, testKey1, sizeof(testKey1)
        ) != PQC_OK)
        std::cout << "\nERROR!!! Failed to get testKey1!\n";


    // Printing our key
    for (int i = 0; i < 32; i++)
        std::cout << int(testKey1[i]) << " ";
    std::cout << "\n\n";

    // delete old container
    PQC_symmetric_container_close(new_container);
    return 0;
}
