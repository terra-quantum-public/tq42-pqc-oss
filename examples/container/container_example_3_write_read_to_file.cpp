#include <iostream>

#include <pqc/aes.h>
#include <pqc/container.h>

/*
In this example, we will write the container to a file and extract the record from the file.
*/

int main()
{

    PQC_CONTAINER_HANDLE new_container = PQC_symmetric_container_create();

    if (new_container == PQC_FAILED_TO_CREATE_CONTAINER)
        std::cout << "\nFailed of container creation\n";


    /*
    Now let's try to save the container to a file.

    You need to understand that you should provide an unique filename to avoid possible collisions.
    Last two arguments used for file encryption: password, salt.
    Salt is recommended to be set to some constant string specific to application.

    After executing the following code file should appear on disk.
    */

    PQC_symmetric_container_save_as(new_container, "some-unique-container-name-write-read.pqc", "password", "salt");
    PQC_symmetric_container_close(new_container);

    /*
    Let's try to use the resulting file to get new key container with old data.
    */

    PQC_CONTAINER_HANDLE container_1_bis =
        PQC_symmetric_container_open("some-unique-container-name-write-read.pqc", "password", "salt");
    if (container_1_bis == PQC_FAILED_TO_CREATE_CONTAINER)
        std::cout << "\nFailed of container creation\n";

    uint8_t testKey[PQC_AES_KEYLEN] = {0};

    if (PQC_symmetric_container_get_key(
            container_1_bis, 0, 100, PQC_CIPHER_AES, PQC_AES_M_ECB, testKey, sizeof(testKey)
        ) != PQC_OK)
        std::cout << "\nERROR!!! Failed to get testKey1!\n";

    PQC_symmetric_container_close(container_1_bis);

    return 0;
}
