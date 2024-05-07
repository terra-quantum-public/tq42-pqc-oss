#include <iostream>
#include <memory>

#include <pqc/aes.h>

/*
In this example, we will create a container, transform it into a special string of bytes,
transform it back.
*/

int main()
{

    PQC_CONTAINER_HANDLE new_container = PQC_symmetric_container_create();
    if (new_container == PQC_FAILED_TO_CREATE_CONTAINER)
        std::cout << "\nFailed of container creation\n";

    const size_t size = PQC_symmetric_container_size(new_container);
    if (size == 0)
        std::cout << "\nFailed container size\n";

    /*
    The container can be converted to a string of bytes using the following code.
    The resulting byte string can be transferred somewhere, written in its current
    form or anything else.
    The resulting string of bytes does not depend on the container. The container
    can be deleted after receiving the data.

    The data string will be received not in its original form, but encrypted. That is,
    the main purpose of the function in the next section of the code is to encrypt the
    data contained in the container.
    To do this, a key is created for the aes algorithm, which must be submitted to the
    function input.
    */
    std::shared_ptr<uint8_t[]> container_data(new uint8_t[size]); // Pointer to buffer to store container data to
    uint8_t creation_key[PQC_AES_KEYLEN] = {
        1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 9,
        1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 9}; // Key AES key used to encrypt container, should point to
                                                         // pqc_aes_key structure or any buffer of size PQC_AES_KEYLEN
    uint8_t creation_iv[PQC_AES_IVLEN] = {
        3, 5, 6, 1, 2, 3, 1, 2, 3,
        1, 2, 3, 1, 2, 3, 9}; // AES initialization vector for container encryption, should point to pqc_aes_iv structure
                              // or any buffer of size PQC_AES_IVLEN
    PQC_symmetric_container_get_data(
        new_container, container_data.get(), size, creation_key, sizeof(creation_key), creation_iv, sizeof(creation_iv)
    );

    /*
    Delete the container.
    We will create a new container from the data previously received from the container.
    New container varriable will be called container_a
    */
    PQC_symmetric_container_close(new_container); // delete old container

    PQC_CONTAINER_HANDLE container_a = PQC_symmetric_container_from_data(
        container_data.get(), size, creation_key, sizeof(creation_key), creation_iv, sizeof(creation_iv)
    );
    if (container_a == PQC_FAILED_TO_CREATE_CONTAINER)
        std::cout << "\nFailed of container_a creation\n";

    PQC_symmetric_container_close(container_a); // delete container

    return 0;
}
