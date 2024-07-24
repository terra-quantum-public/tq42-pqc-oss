#pragma once

#define PQC_PBKDF2_HMAC_SHA3 1

#include "common.h"

#ifdef __cplusplus
extern "C"
{
#endif

    size_t PQC_API PQC_pbkdf_2(
        int mode, size_t hash_length, size_t password_length, const uint8_t * password, size_t key_length,
        uint8_t * derived_key, size_t derived_key_length, uint8_t * salt, size_t salt_length, size_t iterations
    );

    size_t PQC_API PQC_kdf(
        const uint8_t * party_a_info, size_t info_length, const uint8_t * shared_secret, size_t shared_length,
        uint8_t * key, size_t key_length
    );

#ifdef __cplusplus
}
#endif
