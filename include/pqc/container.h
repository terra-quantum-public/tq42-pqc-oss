#pragma once

#include <stddef.h>
#include <stdint.h>

#include "common.h"

typedef size_t PQC_CONTAINER_HANDLE;

#define PQC_BAD_CONTAINER 1
#define PQC_CONTAINER_DEPLETED 7
#define PQC_CONTAINER_EXPIRED 11
#define PQC_FAILED_TO_CREATE_CONTAINER ((PQC_CONTAINER_HANDLE)~0)

#ifdef __cplusplus
extern "C"
{
#endif

    PQC_CONTAINER_HANDLE PQC_API PQC_symmetric_container_create();

    size_t PQC_API PQC_symmetric_container_size(PQC_CONTAINER_HANDLE container);

    uint32_t PQC_API PQC_symmetric_container_get_version(PQC_CONTAINER_HANDLE container);

    uint64_t PQC_API PQC_symmetric_container_get_creation_time(PQC_CONTAINER_HANDLE container);

    uint64_t PQC_API PQC_symmetric_container_get_expiration_time(PQC_CONTAINER_HANDLE container);

    size_t PQC_API PQC_symmetric_container_get_data(
        PQC_CONTAINER_HANDLE container, uint8_t * container_data, size_t data_length, const uint8_t * key,
        size_t key_length, const uint8_t * iv, size_t iv_length
    );

    PQC_CONTAINER_HANDLE PQC_API PQC_symmetric_container_from_data(
        const uint8_t * container_data, size_t data_length, const uint8_t * key, size_t key_length, const uint8_t * iv,
        size_t iv_length
    );

    size_t PQC_API PQC_symmetric_container_save_as(
        PQC_CONTAINER_HANDLE container, const char * filename, const char * password, const char * salt
    );

    size_t PQC_API PQC_symmetric_container_get_key(
        PQC_CONTAINER_HANDLE container, int index, size_t bytes_encoded, uint32_t cipher, uint32_t method,
        uint8_t * key, size_t key_length
    );

    PQC_CONTAINER_HANDLE PQC_API
    PQC_symmetric_container_open(const char * filename, const char * password, const char * salt);

    size_t PQC_API PQC_symmetric_container_close(PQC_CONTAINER_HANDLE container);

    size_t PQC_API PQC_symmetric_container_delete(const char * filename);

    PQC_CONTAINER_HANDLE PQC_API PQC_asymmetric_container_create(uint32_t cipher);

    size_t PQC_API PQC_asymmetric_container_size(PQC_CONTAINER_HANDLE container);

    uint32_t PQC_API PQC_asymmetric_container_get_version(PQC_CONTAINER_HANDLE container);

    uint64_t PQC_API PQC_asymmetric_container_get_creation_time(PQC_CONTAINER_HANDLE container);

    uint64_t PQC_API PQC_asymmetric_container_get_expiration_time(PQC_CONTAINER_HANDLE container);

    size_t PQC_API PQC_asymmetric_container_size_special(uint32_t cipher, uint16_t mode);

    size_t PQC_API PQC_asymmetric_container_get_data(
        PQC_CONTAINER_HANDLE container, uint8_t * container_data, size_t data_length, const uint8_t * key,
        size_t key_length, const uint8_t * iv, size_t iv_length
    );

    PQC_CONTAINER_HANDLE PQC_API PQC_asymmetric_container_from_data(
        uint32_t cipher, const uint8_t * container_data, size_t data_length, const uint8_t * key, size_t key_length,
        const uint8_t * iv, size_t iv_length
    );

    size_t PQC_API PQC_asymmetric_container_put_keys(
        uint32_t cipher, PQC_CONTAINER_HANDLE container, uint8_t * pk, size_t pk_length, uint8_t * sk, size_t sk_length
    );

    size_t PQC_API PQC_asymmetric_container_get_keys(
        uint32_t cipher, PQC_CONTAINER_HANDLE container, uint8_t * pk, size_t pk_length, uint8_t * sk, size_t sk_length
    );

    size_t PQC_API PQC_asymmetric_container_save_as(
        uint32_t cipher, PQC_CONTAINER_HANDLE container, const char * filename, const char * password, const char * salt
    );

    PQC_CONTAINER_HANDLE PQC_API
    PQC_asymmetric_container_open(uint32_t cipher, const char * filename, const char * password, const char * salt);

    size_t PQC_API PQC_asymmetric_container_close(PQC_CONTAINER_HANDLE container);

    size_t PQC_API PQC_asymmetric_container_delete(const char * filename);

#ifdef __cplusplus
}
#endif
