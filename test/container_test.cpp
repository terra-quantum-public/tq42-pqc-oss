#include <gtest/gtest.h>

#include <pqc/aes.h>
#include <pqc/container.h>

TEST(CONTAINER, CONTAINER_WORKFLOW)
{
    uint8_t creation_key[PQC_AES_KEYLEN] = {1, 2, 3};
    uint8_t creation_iv[PQC_AES_IVLEN] = {3, 5, 6};

    CIPHER_HANDLE context = PQC_context_init_randomsource();
    EXPECT_NE(context, PQC_BAD_CONTEXT) << "Context intialization should pass";
    PQC_CONTAINER_HANDLE new_container = PQC_symmetric_container_create(context);

    EXPECT_NE(new_container, PQC_FAILED_TO_CREATE_CONTAINER);

    const size_t size = PQC_symmetric_container_size(new_container);

    EXPECT_NE(size, 0);

    std::shared_ptr<uint8_t[]> container_data(new uint8_t[size]);

    EXPECT_EQ(
        PQC_symmetric_container_get_data(
            new_container, container_data.get(), size, creation_key, sizeof(creation_key), creation_iv,
            sizeof(creation_iv)
        ),
        PQC_OK
    );

    EXPECT_EQ(PQC_symmetric_container_close(new_container), PQC_OK);

    {
        PQC_CONTAINER_HANDLE container_a = PQC_symmetric_container_from_data(
            context, container_data.get(), size, creation_key, sizeof(creation_key), creation_iv, sizeof(creation_iv)
        );

        EXPECT_NE(container_a, PQC_FAILED_TO_CREATE_CONTAINER);

        EXPECT_EQ(
            PQC_symmetric_container_save_as(
                container_a, "CONTAINER.CONTAINER_WORKFLOW-client-device1.pqc", "password", "salt"
            ),
            PQC_OK
        );

        EXPECT_EQ(PQC_symmetric_container_close(container_a), PQC_OK);
    }

    PQC_CONTAINER_HANDLE container_a_bis =
        PQC_symmetric_container_open(context, "CONTAINER.CONTAINER_WORKFLOW-client-device1.pqc", "password", "salt");
    EXPECT_NE(container_a_bis, PQC_FAILED_TO_CREATE_CONTAINER);

    PQC_CONTAINER_HANDLE container_b = PQC_symmetric_container_from_data(
        context, container_data.get(), size, creation_key, sizeof(creation_key), creation_iv, sizeof(creation_iv)
    );
    EXPECT_NE(container_b, PQC_FAILED_TO_CREATE_CONTAINER);

    uint8_t key_a[PQC_AES_KEYLEN] = {0};
    uint8_t key_b[PQC_AES_KEYLEN] = {0};
    uint8_t empty_key[PQC_AES_KEYLEN] = {0};

    EXPECT_EQ(
        PQC_symmetric_container_get_key(container_a_bis, 0, 100, PQC_CIPHER_AES, PQC_AES_M_OFB, key_a, sizeof(key_a)),
        PQC_OK
    );
    EXPECT_EQ(
        PQC_symmetric_container_get_key(container_b, 0, 100, PQC_CIPHER_AES, PQC_AES_M_OFB, key_b, sizeof(key_b)),
        PQC_OK
    );

    EXPECT_EQ(memcmp(key_a, key_b, sizeof(key_a)), 0);
    EXPECT_NE(memcmp(key_a, empty_key, sizeof(key_a)), 0);

    EXPECT_EQ(PQC_symmetric_container_close(container_a_bis), PQC_OK);
    EXPECT_EQ(PQC_symmetric_container_close(container_b), PQC_OK);

    PQC_context_close(context);
}

TEST(CONTAINER, CONTAINER_WORKFLOW_2)
{
    uint8_t creation_key[PQC_AES_KEYLEN] = {1, 2, 3};
    uint8_t creation_iv[PQC_AES_IVLEN] = {4, 5};

    CIPHER_HANDLE context = PQC_context_init_randomsource();
    EXPECT_NE(context, PQC_BAD_CONTEXT) << "Context intialization should pass";

    PQC_CONTAINER_HANDLE new_container = PQC_symmetric_container_create(context);

    EXPECT_NE(new_container, PQC_FAILED_TO_CREATE_CONTAINER);

    const size_t size = PQC_symmetric_container_size(new_container);

    EXPECT_NE(size, 0);

    std::shared_ptr<uint8_t[]> container_data(new uint8_t[size]);

    EXPECT_EQ(
        PQC_symmetric_container_get_data(
            new_container, container_data.get(), size, creation_key, sizeof(creation_key), creation_iv,
            sizeof(creation_iv)
        ),
        PQC_OK
    );

    EXPECT_EQ(PQC_symmetric_container_close(new_container), PQC_OK);

    PQC_CONTAINER_HANDLE container_a = PQC_symmetric_container_from_data(
        context, container_data.get(), size, creation_key, sizeof(creation_key), creation_iv, sizeof(creation_iv)
    );

    EXPECT_NE(container_a, PQC_FAILED_TO_CREATE_CONTAINER);

    EXPECT_EQ(
        PQC_symmetric_container_save_as(
            container_a, "CONTAINER.CONTAINER_WORKFLOW_2-client-device1.pqc", "password", "salt"
        ),
        PQC_OK
    );

    PQC_CONTAINER_HANDLE container_b = PQC_symmetric_container_from_data(
        context, container_data.get(), size, creation_key, sizeof(creation_key), creation_iv, sizeof(creation_iv)
    );
    EXPECT_NE(container_b, PQC_FAILED_TO_CREATE_CONTAINER);

    uint8_t key_a[PQC_AES_KEYLEN] = {0};
    uint8_t key_b[PQC_AES_KEYLEN] = {0};
    uint8_t empty_key[PQC_AES_KEYLEN] = {0};

    EXPECT_EQ(
        PQC_symmetric_container_get_key(container_a, 0, 100, PQC_CIPHER_AES, PQC_AES_M_OFB, key_a, sizeof(key_a)),
        PQC_OK
    );
    EXPECT_EQ(
        PQC_symmetric_container_get_key(container_b, 0, 100, PQC_CIPHER_AES, PQC_AES_M_OFB, key_b, sizeof(key_b)),
        PQC_OK
    );

    EXPECT_EQ(memcmp(key_a, key_b, sizeof(key_a)), 0);
    EXPECT_NE(memcmp(key_a, empty_key, sizeof(key_a)), 0);

    EXPECT_EQ(PQC_symmetric_container_close(container_a), PQC_OK);
    EXPECT_EQ(PQC_symmetric_container_close(container_b), PQC_OK);

    PQC_context_close(context);
}

TEST(CONTAINER, Special)
{
    CIPHER_HANDLE context = PQC_context_init_randomsource();
    EXPECT_NE(context, PQC_BAD_CONTEXT) << "Context intialization should pass";

    PQC_CONTAINER_HANDLE container1 = PQC_symmetric_container_create(context);
    EXPECT_EQ(PQC_symmetric_container_get_version(container1), 1);
    uint64_t creation_ts = PQC_symmetric_container_get_creation_time(container1);
    uint64_t expiration_ts = PQC_symmetric_container_get_expiration_time(container1);
    EXPECT_EQ(creation_ts + 365 * 24 * 3600, expiration_ts);
    EXPECT_EQ(PQC_symmetric_container_close(container1), PQC_OK);

    PQC_CONTAINER_HANDLE container2 = PQC_symmetric_container_create(context);
    EXPECT_EQ(PQC_symmetric_container_get_version(container2), 1);
    EXPECT_EQ(PQC_symmetric_container_close(container2), PQC_OK);

    PQC_CONTAINER_HANDLE containerCl0 = PQC_symmetric_container_create(context);
    PQC_CONTAINER_HANDLE containerCl1 = PQC_symmetric_container_create(context);
    EXPECT_EQ(PQC_symmetric_container_close(containerCl0), PQC_OK);
    EXPECT_EQ(PQC_symmetric_container_close(containerCl1), PQC_OK);

    PQC_context_close(context);
}
