from test import pqc

# In this example, we will create a container, put, get a keys from it, and delete the container.
# In addition, we will get the size of the container.


def test_asymmetric_container(pqc):
    # Creating a asymmetric key container.
    # Encryption algorithms can be symmetric and asymmetric. Examples of a
    # asymmetric cipher: McEliece, Falcon.
    # The container we are creating is designed for asymmetric
    # keys, not suitable for symmetric keys

    # This example will use McEliece keys. Let's create container

    new_container = pqc.PQC_asymmetric_container_create(pqc.PQC_CIPHER_MCELIECE)

    # We can get the size of the key container in bytes using the following code.
    # Additionally, we will check that the size is not zero.

    size = pqc.PQC_asymmetric_container_size(new_container)

    assert size != 0

    version = pqc.PQC_asymmetric_container_get_version(new_container)

    assert version == 1

    creation_ts = pqc.PQC_asymmetric_container_get_creation_time(new_container)
    expiration_ts = pqc.PQC_asymmetric_container_get_expiration_time(new_container)

    assert creation_ts + 365 * 24 * 3600 == expiration_ts

    # This function has second veriant of using. When we have only the cipher type
    # without container. We can get size of the container of this type.
    # Args:
    # cipher type and zero

    size2 = pqc.PQC_asymmetric_container_size_special(pqc.PQC_CIPHER_MCELIECE, 0)

    assert size2 != 0
    assert size == size2

    # So, after creating asymmetric container is empty. There is no control of it.
    # Only user should know, is container empty or not. Now let's generate
    # McEliece keys and put they inside of the container

    pub_alice, priv_alice = pqc.PQC_generate_key_pair(pqc.PQC_CIPHER_MCELIECE)

    pqc.PQC_asymmetric_container_put_keys(pqc.PQC_CIPHER_MCELIECE, new_container, pub_alice, priv_alice)

    # Now there are public and secret keys inside. We can get them out. Let's do it.
    sk_test, pk_test = pqc.PQC_asymmetric_container_get_keys(pqc.PQC_CIPHER_MCELIECE, new_container)

    # keys sould be same with others we had put in. Checking:
    assert pub_alice == pk_test
    assert priv_alice == sk_test

    # delete container
    pqc.PQC_asymmetric_container_close(new_container)


# In this example, we will create container, transform it into a special string of bytes,
# transform it back.


def test_asymmetric_container_from_string(pqc):
    # Creating a asymmetric key container. Generate and put key inside. Cipher McEliece.
    new_container = pqc.PQC_asymmetric_container_create(pqc.PQC_CIPHER_MCELIECE)

    pub_alice, priv_alice = pqc.PQC_generate_key_pair(pqc.PQC_CIPHER_MCELIECE)
    pqc.PQC_asymmetric_container_put_keys(pqc.PQC_CIPHER_MCELIECE, new_container, pub_alice, priv_alice)

    version1 = pqc.PQC_asymmetric_container_get_version(new_container)
    creation_ts1 = pqc.PQC_asymmetric_container_get_creation_time(new_container)
    expiration_ts1 = pqc.PQC_asymmetric_container_get_expiration_time(new_container)

    # We can transform container to the encrypted byte string. Let's do it
    # AES will be used for string encryption
    creation_key = bytes(
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2]
    )
    creation_iv = bytes([9, 8, 7, 6, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6])

    container_data = pqc.PQC_asymmetric_container_get_data(
        new_container, pqc.PQC_asymmetric_container_size(new_container), creation_key, creation_iv
    )

    # Let's restore container from string. The keys inside should be equal with others we generated before

    resultContainer = pqc.PQC_asymmetric_container_from_data(
        pqc.PQC_CIPHER_MCELIECE, container_data, creation_key, creation_iv
    )

    sk_test, pk_test = pqc.PQC_asymmetric_container_get_keys(pqc.PQC_CIPHER_MCELIECE, resultContainer)

    version2 = pqc.PQC_asymmetric_container_get_version(resultContainer)
    creation_ts2 = pqc.PQC_asymmetric_container_get_creation_time(resultContainer)
    expiration_ts2 = pqc.PQC_asymmetric_container_get_expiration_time(resultContainer)

    assert pub_alice == pk_test
    assert priv_alice == sk_test
    assert version1 == version2
    assert creation_ts1 == creation_ts2
    assert expiration_ts1 == expiration_ts2

    pqc.PQC_asymmetric_container_close(new_container)
    pqc.PQC_asymmetric_container_close(resultContainer)


# In this example, we will write the container to a file and extract the record from the file.


def test_asymmetric_container_file_io(pqc):
    # Creating a asymmetric key container. Generate and put key inside. Cipher McEliece.

    new_container = pqc.PQC_asymmetric_container_create(pqc.PQC_CIPHER_MCELIECE)

    pub_alice, priv_alice = pqc.PQC_generate_key_pair(pqc.PQC_CIPHER_MCELIECE)

    pqc.PQC_asymmetric_container_put_keys(pqc.PQC_CIPHER_MCELIECE, new_container, pub_alice, priv_alice)

    version1 = pqc.PQC_asymmetric_container_get_version(new_container)
    creation_ts1 = pqc.PQC_asymmetric_container_get_creation_time(new_container)
    expiration_ts1 = pqc.PQC_asymmetric_container_get_expiration_time(new_container)

    # Now let's try to save the container to a file.
    pqc.PQC_asymmetric_container_save_as(
        pqc.PQC_CIPHER_MCELIECE,
        new_container,
        "test_asymmetric_container_file_io.pqc",
        "password",
        "salt",
    )

    # Let's create new container, get kes from file and compare with old keys

    resultContainer = pqc.PQC_asymmetric_container_open(
        pqc.PQC_CIPHER_MCELIECE, "test_asymmetric_container_file_io.pqc", "password", "salt"
    )

    sk_test, pk_test = pqc.PQC_asymmetric_container_get_keys(pqc.PQC_CIPHER_MCELIECE, resultContainer)

    version2 = pqc.PQC_asymmetric_container_get_version(resultContainer)
    creation_ts2 = pqc.PQC_asymmetric_container_get_creation_time(resultContainer)
    expiration_ts2 = pqc.PQC_asymmetric_container_get_expiration_time(resultContainer)

    assert pub_alice == pk_test
    assert priv_alice == sk_test
    assert version1 == version2
    assert creation_ts1 == creation_ts2
    assert expiration_ts1 == expiration_ts2

    pqc.PQC_asymmetric_container_close(new_container)
    pqc.PQC_asymmetric_container_close(resultContainer)


def test_asymmetric_container_file_delete(pqc):
    # Creating a asymmetric key container. Generate and put key inside. Cipher McEliece.

    new_container = pqc.PQC_asymmetric_container_create(pqc.PQC_CIPHER_MCELIECE)

    pub_alice, priv_alice = pqc.PQC_generate_key_pair(pqc.PQC_CIPHER_MCELIECE)

    pqc.PQC_asymmetric_container_put_keys(pqc.PQC_CIPHER_MCELIECE, new_container, pub_alice, priv_alice)

    # Now let's try to save the container to a file.
    pqc.PQC_asymmetric_container_save_as(
        pqc.PQC_CIPHER_MCELIECE,
        new_container,
        "test_asymmetric_container_file_delete.pqc",
        "password",
        "salt",
    )
    pqc.PQC_asymmetric_container_close(new_container)
    pqc.PQC_asymmetric_container_delete("test_asymmetric_container_file_delete.pqc")
