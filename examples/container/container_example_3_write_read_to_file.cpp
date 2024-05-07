#include <iostream>

#include <pqc/aes.h>

/*
In this example, we will write the container to a file and extract the record from the file.
*/

int main()
{

    PQC_CONTAINER_HANDLE new_container = PQC_symmetric_container_create();

    if (new_container == PQC_FAILED_TO_CREATE_CONTAINER)
        std::cout << "\nFailed of container creation\n";


    /*
    Now let's try to save the container to a file. This can be done using one of the
    save to file functions. There are only two such functions. They differ only in the
    name of the files that will be generated.

    You need to understand that there are several arguments in functions besides the
    container that needs to be saved. They are all textual. All of them are used to
    create a file name except two: password, salt.
    - password: password used to encrypt file
    - salt: salt to be used in file encryption. It is recommended to be set to some
    constant string specific to application.

    After executing the following code, two files should appear. They both contain a
    container with the same keys. They differ in names.

    Use only one saving to one container.
    The example of the second variant of saving call:
    */
    PQC_symmetric_container_save_as_pair(new_container, "client2", "device2", "password", "salt");


    PQC_symmetric_container_save_as(new_container, "server", "client1", "device1", "password", "salt");
    PQC_symmetric_container_close(new_container); // close new_container;


    /*
    Let's try to count the resulting files to get new key containers with old data.
    If you used second another function of saving to file, the call of reading will be:
    PQC_CONTAINER_HANDLE container_2_bis = PQC_symmetric_container_pair_open("client2", "device2", "password", "salt");
    */

    PQC_CONTAINER_HANDLE container_1_bis =
        PQC_symmetric_container_open("server", "client1", "device1", "password", "salt");
    if (container_1_bis == PQC_FAILED_TO_CREATE_CONTAINER)
        std::cout << "\nFailed of container creation\n";

    uint8_t testKey1[PQC_AES_KEYLEN] = {0};

    if (PQC_symmetric_container_get_key(
            container_1_bis, 0, 100, PQC_CIPHER_AES, PQC_AES_M_ECB, testKey1, sizeof(testKey1)
        ) != PQC_OK)
        std::cout << "\nERROR!!! Failed to get testKey1!\n";


    PQC_CONTAINER_HANDLE container_2_bis = PQC_symmetric_container_pair_open("client2", "device2", "password", "salt");
    if (container_2_bis == PQC_FAILED_TO_CREATE_CONTAINER)
        std::cout << "\nFailed of container creation\n";

    uint8_t testKey2[PQC_AES_KEYLEN] = {0};

    if (PQC_symmetric_container_get_key(
            container_2_bis, 0, 100, PQC_CIPHER_AES, PQC_AES_M_ECB, testKey2, sizeof(testKey2)
        ) != PQC_OK)
        std::cout << "\nERROR!!! Failed to get testKey2!\n";

    std::cout << container_1_bis << " " << container_2_bis << std::endl;

    PQC_symmetric_container_close(container_1_bis); // close new_container;
    PQC_symmetric_container_close(container_2_bis); // close new_container;

    return 0;
}
