from test import pqc


# In this test, we will create a container, get a key from it, and delete the container.
# In addition, we will get the size of the container.


def test_symmetric_container(pqc):
    # Creating a symmetric key container for AES encryption.
    new_container = pqc.PQC_symmetric_container_create()

    # Assert the size is not empty
    size = pqc.PQC_symmetric_container_size(new_container)
    assert size > 0, f"Container is improperly initialized with size {size}"

    # Verification the version of the symmetric key container and checking the type.
    version = pqc.PQC_symmetric_container_get_version(new_container)
    expected_version = 1
    assert isinstance(version, int), "Version should be an integer."
    assert version == expected_version, f"Container version mismatch: expected {expected_version}, got {version}"


    # Checking that the expiration time is exactly one year (in seconds) after the creation time.

    creation_ts = pqc.PQC_symmetric_container_get_creation_time(new_container);
    expiration_ts = pqc.PQC_symmetric_container_get_expiration_time(new_container);
    expected_lifetime = 365 * 24 * 3600
    assert expiration_ts == creation_ts + expected_lifetime, "Expiration timestamp does not match the expected lifetime."


    # Checking the key search to confirm the functionality.
    try:
        key = pqc.PQC_symmetric_container_get_key(new_container, 0, 100, pqc.PQC_CIPHER_AES, pqc.PQC_AES_M_ECB)
        assert isinstance(key, bytes), "Returned key should be of bytes type."
        expected_key_length = pqc.PQC_AES_KEYLEN
        assert len(key) == expected_key_length, f"Expected key length to be {expected_key_length}, but got {len(key)}"
    except Exception as e:
        assert False, f"An unexpected error occurred while retrieving the key under normal conditions: {e}"


    pqc.PQC_symmetric_container_close(new_container)


# In this test, we will create a container, transform it into a special string of bytes,
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
    version1 = pqc.PQC_symmetric_container_get_version(new_container)
    creation_ts1 = pqc.PQC_symmetric_container_get_creation_time(new_container)
    expiration_ts1 = pqc.PQC_symmetric_container_get_expiration_time(new_container)

    # Delete the container.
    # We will create a new container from the data previously received from the container.
    # New container varriable will be called container_a

    pqc.PQC_symmetric_container_close(new_container)  # delete old container

    container_a = pqc.PQC_symmetric_container_from_data(container_data, creation_key, creation_iv)

    testKey2 = pqc.PQC_symmetric_container_get_key(container_a, 0, 100, pqc.PQC_CIPHER_AES, pqc.PQC_AES_M_ECB)
    version2 = pqc.PQC_symmetric_container_get_version(container_a)
    creation_ts2 = pqc.PQC_symmetric_container_get_creation_time(container_a)
    expiration_ts2 = pqc.PQC_symmetric_container_get_expiration_time(container_a)

    assert testKey1 == testKey2
    assert version1 == version2
    assert creation_ts1 == creation_ts2
    assert expiration_ts1 == expiration_ts2

    pqc.PQC_symmetric_container_close(container_a)  # delete container


# In this test, we will write the container to a file and extract the record from the file.


def test_symmetric_container_file_io(pqc):
    new_container = pqc.PQC_symmetric_container_create()

    # Now let's try to save the container to a file.
    # You need to understand that you should provide an unique filename to avoid possible collisions.
    # Last two arguments used for file encryption: password, salt.
    # Salt is recommended to be set to some constant string specific to application.
    # After executing the following code file should appear on disk.

    pqc.PQC_symmetric_container_save_as(
        new_container, "test_symmetric_container_file_io-1.pqc", "password", "salt"
    )

    testKey1 = pqc.PQC_symmetric_container_get_key(new_container, 0, 100, pqc.PQC_CIPHER_AES, pqc.PQC_AES_M_OFB)
    version1 = pqc.PQC_symmetric_container_get_version(new_container)
    creation_ts1 = pqc.PQC_symmetric_container_get_creation_time(new_container)
    expiration_ts1 = pqc.PQC_symmetric_container_get_expiration_time(new_container)

    pqc.PQC_symmetric_container_close(new_container)

    container_io = pqc.PQC_symmetric_container_open(
        "test_symmetric_container_file_io-1.pqc", "password", "salt"
    )
    testKey2 = pqc.PQC_symmetric_container_get_key(container_io, 0, 100, pqc.PQC_CIPHER_AES, pqc.PQC_AES_M_OFB)
    version2 = pqc.PQC_symmetric_container_get_version(container_io)
    creation_ts2 = pqc.PQC_symmetric_container_get_creation_time(container_io)
    expiration_ts2 = pqc.PQC_symmetric_container_get_expiration_time(container_io)
    pqc.PQC_symmetric_container_close(container_io)

    assert testKey1 == testKey2
    assert version1 == version2
    assert creation_ts1 == creation_ts2
    assert expiration_ts1 == expiration_ts2


def test_symmetric_container_file_delete(pqc):
    new_container = pqc.PQC_symmetric_container_create()

    pqc.PQC_symmetric_container_save_as(
        new_container, "test_symmetric_container_file_delete.pqc", "password", "salt"
    )

    pqc.PQC_symmetric_container_close(new_container)

    pqc.PQC_symmetric_container_delete("test_symmetric_container_file_delete.pqc")
