from test import pqc


# In this example, we will create a container, get a key from it, and delete the container.
# In addition, we will get the size of the container.


def test_symmetric_container(pqc):
    # Creating a symmetric key container.
    # Encryption algorithms can be symmetric and asymmetric. Example of a
    # symmetric cipher: aes. The container we are creating is designed for symmetric
    # keys, not suitable for asymmetric keys
    new_container = pqc.PQC_symmetric_container_create()

    # We can get the size of the key container in bytes using the following code.
    # Additionally, we will check that the size is not zero.

    size = pqc.PQC_symmetric_container_size(new_container)

    assert size != 0

    pqc.PQC_symmetric_container_close(new_container)


# In this example, we will create a container, transform it into a special string of bytes,
# transform it back.


def test_symmetric_container_from_string(pqc):
    new_container = pqc.PQC_symmetric_container_create()

    size = pqc.PQC_symmetric_container_size(new_container)

    assert size != 0

    # The container can be converted to a string of bytes using the following code.
    # The resulting byte string can be transferred somewhere, written in its current
    # form or anything else.
    # The resulting string of bytes does not depend on the container. The container
    # can be deleted after receiving the data.

    # The data string will be received not in its original form, but encrypted. That is,
    # the main purpose of the function in the next section of the code is to encrypt the
    # data contained in the container.
    # To do this, a key is created for the aes algorithm, which must be submitted to the
    # function input.

    creation_key = bytes(
        [1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 9, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 9]
    )  # Key AES key used to encrypt container, should point to pqc_aes_key structure or any buffer of size PQC_AES_KEYLEN
    creation_iv = bytes(
        [3, 5, 6, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 9]
    )  # AES initialization vector for container encryption, should point to pqc_aes_iv structure or any buffer of size PQC_AES_IVLEN

    container_data = pqc.PQC_symmetric_container_get_data(new_container, creation_key, creation_iv)

    testKey1 = pqc.PQC_symmetric_container_get_key(new_container, 0, 100, pqc.PQC_CIPHER_AES, pqc.PQC_AES_M_ECB)

    # Delete the container.
    # We will create a new container from the data previously received from the container.
    # New container varriable will be called container_a

    pqc.PQC_symmetric_container_close(new_container)  # delete old container

    container_a = pqc.PQC_symmetric_container_from_data(container_data, creation_key, creation_iv)

    testKey2 = pqc.PQC_symmetric_container_get_key(container_a, 0, 100, pqc.PQC_CIPHER_AES, pqc.PQC_AES_M_ECB)

    assert testKey1 == testKey2

    pqc.PQC_symmetric_container_close(container_a)  # delete container


# In this example, we will write the container to a file and extract the record from the file.


def test_symmetric_container_file_io(pqc):
    new_container = pqc.PQC_symmetric_container_create()

    # Now let's try to save the container to a file. This can be done using one of the
    # save to file functions. There are only two such functions. They differ only in the
    # name of the files that will be generated.

    # You need to understand that there are several arguments in functions besides the
    # container that needs to be saved. They are all textual. All of them are used to
    # create a file name except two: password, salt.
    # - password: password used to encrypt file
    # - salt: salt to be used in file encryption. It is recommended to be set to some
    # constant string specific to application.

    # After executing the following code, two files should appear. They both contain a
    # container with the same keys. They differ in names.

    # Use only one saving to one container.
    # The example of the second variant of saving call:

    pqc.PQC_symmetric_container_save_as_pair(
        new_container, "test_symmetric_container_file_io", "device2", "password", "salt"
    )

    pqc.PQC_symmetric_container_save_as(
        new_container, "test_symmetric_container_file_io", "client1", "device1", "password", "salt"
    )

    testKey1 = pqc.PQC_symmetric_container_get_key(new_container, 0, 100, pqc.PQC_CIPHER_AES, pqc.PQC_AES_M_OFB)

    pqc.PQC_symmetric_container_close(new_container)  # close new_container;

    # Let's try to count the resulting files to get new key containers with old data.
    # If you used second another function of saving to file, the call of reading will be:
    container_2 = pqc.PQC_symmetric_container_pair_open(
        "test_symmetric_container_file_io", "device2", "password", "salt"
    )
    testKey2 = pqc.PQC_symmetric_container_get_key(container_2, 0, 100, pqc.PQC_CIPHER_AES, pqc.PQC_AES_M_OFB)

    container_3 = pqc.PQC_symmetric_container_open(
        "test_symmetric_container_file_io", "client1", "device1", "password", "salt"
    )
    testKey3 = pqc.PQC_symmetric_container_get_key(container_3, 0, 100, pqc.PQC_CIPHER_AES, pqc.PQC_AES_M_OFB)
    pqc.PQC_symmetric_container_close(container_2)
    pqc.PQC_symmetric_container_close(container_3)

    assert testKey1 == testKey2
    assert testKey1 == testKey3


def test_symmetric_container_file_delete(pqc):
    new_container = pqc.PQC_symmetric_container_create()

    pqc.PQC_symmetric_container_save_as_pair(
        new_container, "test_symmetric_container_file_delete", "device2", "password", "salt"
    )

    pqc.PQC_symmetric_container_save_as(
        new_container, "test_symmetric_container_file_delete", "client1", "device1", "password", "salt"
    )

    pqc.PQC_symmetric_container_close(new_container)

    pqc.PQC_symmetric_container_delete("test_symmetric_container_file_delete", "client1", "device1")
    pqc.PQC_symmetric_container_pair_delete("test_symmetric_container_file_delete", "device2")
