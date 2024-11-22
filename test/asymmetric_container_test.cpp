#include <vector>

#include <gtest/gtest.h>

#include <pqc/aes.h>
#include <pqc/container.h>
#include <pqc/falcon.h>
#include <pqc/mceliece.h>

#define MCELIECE_PRIVATE(x) std::vector<uint8_t> x(sizeof(pqc_mceliece_private_key))
#define MCELIECE_PUBLIC(x) std::vector<uint8_t> x(sizeof(pqc_mceliece_public_key))

#define FALCON_PRIVATE(x) std::vector<uint8_t> x(sizeof(pqc_falcon_private_key))
#define FALCON_PUBLIC(x) std::vector<uint8_t> x(sizeof(pqc_falcon_public_key))

TEST(ASYMMETRIC_CONTAINER, ASYMMETRIC_CONTAINERS_CREATING)
{
    PQC_CONTAINER_HANDLE new_container = PQC_asymmetric_container_create(PQC_CIPHER_MCELIECE);
    EXPECT_NE(new_container, PQC_FAILED_TO_CREATE_CONTAINER);
    EXPECT_EQ(PQC_asymmetric_container_close(new_container), PQC_OK);

    new_container = PQC_asymmetric_container_create(PQC_CIPHER_MCELIECE);
    EXPECT_NE(new_container, PQC_FAILED_TO_CREATE_CONTAINER);
    EXPECT_EQ(PQC_asymmetric_container_close(new_container), PQC_OK);
}

TEST(ASYMMETRIC_CONTAINER, ASYMMETRIC_CONTAINER_KeyGen_Put)
{
    PQC_CONTAINER_HANDLE new_container = PQC_asymmetric_container_create(PQC_CIPHER_MCELIECE);
    EXPECT_NE(new_container, PQC_FAILED_TO_CREATE_CONTAINER);

    MCELIECE_PRIVATE(priv_alice);
    MCELIECE_PUBLIC(pub_alice);

    EXPECT_EQ(
        PQC_keypair_generate(
            PQC_CIPHER_MCELIECE, pub_alice.data(), pub_alice.size(), priv_alice.data(), priv_alice.size()
        ),
        PQC_OK
    );

    EXPECT_EQ(
        PQC_asymmetric_container_put_keys(
            PQC_CIPHER_MCELIECE, new_container, pub_alice.data(), pub_alice.size(), priv_alice.data(), priv_alice.size()
        ),
        PQC_OK
    );

    MCELIECE_PRIVATE(sk_test);
    MCELIECE_PUBLIC(pk_test);

    EXPECT_EQ(
        PQC_asymmetric_container_get_keys(
            PQC_CIPHER_MCELIECE, new_container, pk_test.data(), pk_test.size(), sk_test.data(), sk_test.size()
        ),
        PQC_OK
    );

    EXPECT_EQ(pub_alice, pk_test);
    EXPECT_EQ(priv_alice, sk_test);

    EXPECT_EQ(PQC_asymmetric_container_close(new_container), PQC_OK);
}

TEST(ASYMMETRIC_CONTAINER, ASYMMETRIC_CONTAINER_ToFrom_DATA)
{
    PQC_CONTAINER_HANDLE new_container = PQC_asymmetric_container_create(PQC_CIPHER_MCELIECE);
    EXPECT_NE(new_container, PQC_FAILED_TO_CREATE_CONTAINER);

    MCELIECE_PRIVATE(priv_alice);
    MCELIECE_PUBLIC(pub_alice);

    EXPECT_EQ(
        PQC_keypair_generate(
            PQC_CIPHER_MCELIECE, pub_alice.data(), pub_alice.size(), priv_alice.data(), priv_alice.size()
        ),
        PQC_OK
    );

    EXPECT_EQ(
        PQC_asymmetric_container_put_keys(
            PQC_CIPHER_MCELIECE, new_container, pub_alice.data(), pub_alice.size(), priv_alice.data(), priv_alice.size()
        ),
        PQC_OK
    );

    std::vector<uint8_t> container_data(PQC_asymmetric_container_size(new_container));

    uint8_t creation_key[PQC_AES_KEYLEN] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6,
                                            7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2};
    uint8_t creation_iv[PQC_AES_IVLEN] = {9, 8, 7, 6, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6};

    EXPECT_EQ(
        PQC_asymmetric_container_get_data(
            new_container, container_data.data(), container_data.size(), creation_key, PQC_AES_KEYLEN, creation_iv,
            PQC_AES_IVLEN
        ),
        PQC_OK
    );

    PQC_CONTAINER_HANDLE resultContainer = PQC_asymmetric_container_from_data(
        PQC_CIPHER_MCELIECE, container_data.data(), container_data.size(), creation_key, PQC_AES_KEYLEN, creation_iv,
        PQC_AES_IVLEN
    );
    EXPECT_NE(resultContainer, PQC_FAILED_TO_CREATE_CONTAINER);

    EXPECT_EQ(
        PQC_asymmetric_container_get_version(new_container), PQC_asymmetric_container_get_version(resultContainer)
    );
    EXPECT_EQ(
        PQC_asymmetric_container_get_creation_time(new_container),
        PQC_asymmetric_container_get_creation_time(resultContainer)
    );
    EXPECT_EQ(
        PQC_asymmetric_container_get_expiration_time(new_container),
        PQC_asymmetric_container_get_expiration_time(resultContainer)
    );

    MCELIECE_PRIVATE(sk_test);
    MCELIECE_PUBLIC(pk_test);

    EXPECT_EQ(
        PQC_asymmetric_container_get_keys(
            PQC_CIPHER_MCELIECE, resultContainer, pk_test.data(), pk_test.size(), sk_test.data(), sk_test.size()
        ),
        PQC_OK
    );

    EXPECT_EQ(pub_alice, pk_test);
    EXPECT_EQ(priv_alice, sk_test);

    EXPECT_EQ(PQC_asymmetric_container_close(new_container), PQC_OK);

    EXPECT_EQ(PQC_asymmetric_container_close(resultContainer), PQC_OK);
}

TEST(ASYMMETRIC_CONTAINER, ASYMMETRIC_CONTAINER_ToFromFile)
{
    PQC_CONTAINER_HANDLE new_container = PQC_asymmetric_container_create(PQC_CIPHER_MCELIECE);
    EXPECT_NE(new_container, PQC_FAILED_TO_CREATE_CONTAINER);

    MCELIECE_PRIVATE(priv_alice);
    MCELIECE_PUBLIC(pub_alice);

    EXPECT_EQ(
        PQC_keypair_generate(
            PQC_CIPHER_MCELIECE, pub_alice.data(), pub_alice.size(), priv_alice.data(), priv_alice.size()
        ),
        PQC_OK
    );

    EXPECT_EQ(
        PQC_asymmetric_container_put_keys(
            PQC_CIPHER_MCELIECE, new_container, pub_alice.data(), pub_alice.size(), priv_alice.data(), priv_alice.size()
        ),
        PQC_OK
    );

    EXPECT_EQ(
        PQC_asymmetric_container_save_as(
            PQC_CIPHER_MCELIECE, new_container,
            "ASYMMETRIC_CONTAINER.ASYMMETRIC_CONTAINER_ToFromFile-client-device1.pqc", "password", "salt"
        ),
        PQC_OK
    );

    PQC_CONTAINER_HANDLE resultContainer = PQC_asymmetric_container_open(
        PQC_CIPHER_MCELIECE, "ASYMMETRIC_CONTAINER.ASYMMETRIC_CONTAINER_ToFromFile-client-device1.pqc", "password",
        "salt"
    );
    EXPECT_NE(resultContainer, PQC_FAILED_TO_CREATE_CONTAINER);

    EXPECT_EQ(
        PQC_asymmetric_container_get_version(new_container), PQC_asymmetric_container_get_version(resultContainer)
    );
    EXPECT_EQ(
        PQC_asymmetric_container_get_creation_time(new_container),
        PQC_asymmetric_container_get_creation_time(resultContainer)
    );
    EXPECT_EQ(
        PQC_asymmetric_container_get_expiration_time(new_container),
        PQC_asymmetric_container_get_expiration_time(resultContainer)
    );

    MCELIECE_PRIVATE(sk_test);
    MCELIECE_PUBLIC(pk_test);

    EXPECT_EQ(
        PQC_asymmetric_container_get_keys(
            PQC_CIPHER_MCELIECE, resultContainer, pk_test.data(), pk_test.size(), sk_test.data(), sk_test.size()
        ),
        PQC_OK
    );

    EXPECT_EQ(pub_alice, pk_test);
    EXPECT_EQ(priv_alice, sk_test);

    EXPECT_EQ(PQC_asymmetric_container_close(new_container), PQC_OK);

    EXPECT_EQ(PQC_asymmetric_container_close(resultContainer), PQC_OK);
}

TEST(ASYMMETRIC_CONTAINER, ASYMMETRIC_CONTAINER_McEliece_ToFrom_DATA)
{
    PQC_CONTAINER_HANDLE new_container = PQC_asymmetric_container_create(PQC_CIPHER_MCELIECE);
    EXPECT_NE(new_container, PQC_FAILED_TO_CREATE_CONTAINER);

    std::vector<uint8_t> priv_alice(sizeof(pqc_mceliece_private_key));
    std::vector<uint8_t> pub_alice(sizeof(pqc_mceliece_public_key));

    EXPECT_EQ(
        PQC_keypair_generate(
            PQC_CIPHER_MCELIECE, pub_alice.data(), pub_alice.size(), priv_alice.data(), priv_alice.size()
        ),
        PQC_OK
    );

    EXPECT_EQ(
        PQC_asymmetric_container_put_keys(
            PQC_CIPHER_MCELIECE, new_container, pub_alice.data(), pub_alice.size(), priv_alice.data(), priv_alice.size()
        ),
        PQC_OK
    );

    std::vector<uint8_t> container_data(PQC_asymmetric_container_size(new_container));

    uint8_t creation_key[PQC_AES_KEYLEN] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6,
                                            7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2};
    uint8_t creation_iv[PQC_AES_IVLEN] = {9, 8, 7, 6, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6};

    EXPECT_EQ(
        PQC_asymmetric_container_get_data(
            new_container, container_data.data(), container_data.size(), creation_key, PQC_AES_KEYLEN, creation_iv,
            PQC_AES_IVLEN
        ),
        PQC_OK
    );

    PQC_CONTAINER_HANDLE resultContainer = PQC_asymmetric_container_from_data(
        PQC_CIPHER_MCELIECE, container_data.data(), container_data.size(), creation_key, PQC_AES_KEYLEN, creation_iv,
        PQC_AES_IVLEN
    );
    EXPECT_NE(resultContainer, PQC_FAILED_TO_CREATE_CONTAINER);

    EXPECT_EQ(
        PQC_asymmetric_container_get_version(new_container), PQC_asymmetric_container_get_version(resultContainer)
    );
    EXPECT_EQ(
        PQC_asymmetric_container_get_creation_time(new_container),
        PQC_asymmetric_container_get_creation_time(resultContainer)
    );
    EXPECT_EQ(
        PQC_asymmetric_container_get_expiration_time(new_container),
        PQC_asymmetric_container_get_expiration_time(resultContainer)
    );

    std::vector<uint8_t> sk_test(sizeof(pqc_mceliece_private_key));
    std::vector<uint8_t> pk_test(sizeof(pqc_mceliece_public_key));

    EXPECT_EQ(
        PQC_asymmetric_container_get_keys(
            PQC_CIPHER_MCELIECE, resultContainer, pk_test.data(), pk_test.size(), sk_test.data(), sk_test.size()
        ),
        PQC_OK
    );

    EXPECT_EQ(pub_alice, pk_test);
    EXPECT_EQ(priv_alice, sk_test);

    EXPECT_EQ(PQC_asymmetric_container_close(new_container), PQC_OK);
    EXPECT_EQ(PQC_asymmetric_container_close(resultContainer), PQC_OK);
}

TEST(ASYMMETRIC_CONTAINER, ASYMMETRIC_CONTAINER_ToFrom_DATA_IncorrectedCiphers)
{
    PQC_CONTAINER_HANDLE new_container = PQC_asymmetric_container_create(PQC_CIPHER_FALCON);
    EXPECT_NE(new_container, PQC_FAILED_TO_CREATE_CONTAINER);

    FALCON_PRIVATE(priv_alice);
    FALCON_PUBLIC(pub_alice);

    EXPECT_EQ(
        PQC_keypair_generate(
            PQC_CIPHER_FALCON, pub_alice.data(), pub_alice.size(), priv_alice.data(), priv_alice.size()
        ),
        PQC_OK
    );

    EXPECT_NE(
        PQC_asymmetric_container_put_keys(
            PQC_CIPHER_MCELIECE, new_container, pub_alice.data(), pub_alice.size(), priv_alice.data(), priv_alice.size()
        ),
        PQC_OK
    );

    std::vector<uint8_t> container_data(PQC_asymmetric_container_size(new_container));

    uint8_t creation_key[PQC_AES_KEYLEN] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6,
                                            7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2};
    uint8_t creation_iv[PQC_AES_IVLEN] = {9, 8, 7, 6, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6};

    EXPECT_EQ(
        PQC_asymmetric_container_get_data(
            new_container, container_data.data(), container_data.size(), creation_key, PQC_AES_KEYLEN, creation_iv,
            PQC_AES_IVLEN
        ),
        PQC_OK
    );

    PQC_CONTAINER_HANDLE resultContainer = PQC_asymmetric_container_from_data(
        PQC_CIPHER_FALCON, container_data.data(), container_data.size(), creation_key, PQC_AES_KEYLEN, creation_iv,
        PQC_AES_IVLEN
    );
    EXPECT_NE(resultContainer, PQC_FAILED_TO_CREATE_CONTAINER);

    FALCON_PRIVATE(sk_test);
    FALCON_PUBLIC(pk_test);

    EXPECT_NE(
        PQC_asymmetric_container_get_keys(
            PQC_CIPHER_MCELIECE, resultContainer, pk_test.data(), pk_test.size(), sk_test.data(), sk_test.size()
        ),
        PQC_OK
    );

    EXPECT_EQ(PQC_asymmetric_container_close(new_container), PQC_OK);
    EXPECT_EQ(PQC_asymmetric_container_close(resultContainer), PQC_OK);
}

TEST(ASYMMETRIC_CONTAINER, Special)
{
    PQC_CONTAINER_HANDLE container1_ = PQC_asymmetric_container_create(PQC_CIPHER_MCELIECE);
    EXPECT_EQ(PQC_asymmetric_container_get_version(container1_), 1);
    uint64_t creation_ts = PQC_asymmetric_container_get_creation_time(container1_);
    uint64_t expiration_ts = PQC_asymmetric_container_get_expiration_time(container1_);
    EXPECT_EQ(creation_ts + 365 * 24 * 3600, expiration_ts);
    EXPECT_EQ(PQC_asymmetric_container_close(container1_), PQC_OK);

    PQC_CONTAINER_HANDLE container2_ = PQC_asymmetric_container_create(PQC_CIPHER_MCELIECE);
    EXPECT_EQ(PQC_asymmetric_container_close(container2_), PQC_OK);

    PQC_CONTAINER_HANDLE containerAs0 = PQC_asymmetric_container_create(PQC_CIPHER_MCELIECE);
    PQC_CONTAINER_HANDLE containerAs1 = PQC_asymmetric_container_create(PQC_CIPHER_MCELIECE);
    EXPECT_EQ(PQC_asymmetric_container_close(containerAs0), PQC_OK);
    EXPECT_EQ(PQC_asymmetric_container_close(containerAs1), PQC_OK);
}
