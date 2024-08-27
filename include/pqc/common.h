#pragma once

#include <stddef.h>
#include <stdint.h>

typedef size_t CIPHER_HANDLE;

// Return codes
#define PQC_OK 0
#define PQC_BAD_CONTEXT 1
#define PQC_BAD_LEN 2
#define PQC_BAD_MODE 3
#define PQC_NO_IV 4
#define PQC_INTERNAL_ERROR 5
#define PQC_BAD_SIGNATURE 6
#define PQC_IO_ERROR 8
#define PQC_BAD_CIPHER ((CIPHER_HANDLE)~0)
#define PQC_AUTHENTICATION_FAILURE 9

#if defined(_WIN32) || defined(WIN32)
#define PQC_CALLBACK __stdcall
#else
#define PQC_CALLBACK
#endif

#ifdef __unix__
#define PQC_API
#elif defined(__APPLE__)
#define PQC_API
#elif defined(_WIN32) || defined(WIN32)
#ifdef PQC_SHARED
#ifdef PQC_EXPORTS
#define PQC_API __declspec(dllexport)
#else
#define PQC_API __declspec(dllimport)
#endif
#else
#define PQC_API
#endif
#endif

#ifdef __cplusplus
extern "C"
{
#endif

    size_t PQC_API PQC_generate_key_pair(
        uint32_t cipher, uint8_t * public_key, size_t public_size, uint8_t * private_key, size_t private_size
    );

    CIPHER_HANDLE PQC_API PQC_init_context(uint32_t cipher, const uint8_t * key, size_t key_length);
    CIPHER_HANDLE PQC_API
    PQC_init_context_iv(uint32_t cipher, const uint8_t * key, size_t key_length, const uint8_t * iv, size_t iv_length);
    CIPHER_HANDLE PQC_API PQC_init_context_hash(uint32_t algorithm, uint32_t mode);

    size_t PQC_API PQC_set_iv(CIPHER_HANDLE ctx, const uint8_t * iv, size_t iv_length);

    size_t PQC_API PQC_encrypt(CIPHER_HANDLE ctx, uint32_t mode, uint8_t * buffer, size_t length);

    size_t PQC_API PQC_decrypt(CIPHER_HANDLE ctx, uint32_t mode, uint8_t * buffer, size_t length);

    size_t PQC_API PQC_aead_encrypt(
        CIPHER_HANDLE ctx, uint32_t mode, uint8_t * buffer, size_t length, const uint8_t * aad, size_t aad_length,
        uint8_t * auth_tag, size_t auth_tag_len
    );

    size_t PQC_API PQC_aead_decrypt(
        CIPHER_HANDLE ctx, uint32_t mode, uint8_t * buffer, size_t length, const uint8_t * aad, size_t aad_length,
        const uint8_t * auth_tag, size_t auth_tag_len
    );

    size_t PQC_API PQC_aead_check(
        CIPHER_HANDLE ctx, uint32_t mode, uint8_t * buffer, size_t length, const uint8_t * aad, size_t aad_length,
        const uint8_t * auth_tag, size_t auth_tag_len
    );

    size_t PQC_API PQC_kem_encode_secret(
        uint32_t cipher, uint8_t * message, size_t message_length, const uint8_t * public_key, size_t key_length,
        uint8_t * shared_secret, size_t shared_secret_length
    );

    size_t PQC_API PQC_kem_decode_secret(
        CIPHER_HANDLE ctx, const uint8_t * message, size_t message_length, uint8_t * shared_secret,
        size_t shared_secret_length
    );

    size_t PQC_API PQC_kem_encode(
        uint32_t cipher, uint8_t * message, size_t message_length, const uint8_t * party_a_info, size_t info_length,
        const uint8_t * public_key, size_t key_length, uint8_t * shared_key, size_t shared_key_length
    );

    size_t PQC_API PQC_kem_decode(
        CIPHER_HANDLE ctx, const uint8_t * message, size_t message_length, const uint8_t * party_a_info,
        size_t info_length, uint8_t * shared_key, size_t shared_key_length
    );


    size_t PQC_API
    PQC_sign(CIPHER_HANDLE ctx, const uint8_t * buffer, size_t length, uint8_t * signature, size_t signature_len);
    size_t PQC_API PQC_verify(
        uint32_t cipher, const uint8_t * public_key, size_t public_keylen, const uint8_t * buffer, size_t length,
        const uint8_t * signature, size_t signature_len
    );

    size_t PQC_API PQC_add_data(CIPHER_HANDLE ctx, const uint8_t * buffer, size_t length);
    size_t PQC_API PQC_hash_size(CIPHER_HANDLE ctx);
    size_t PQC_API PQC_get_hash(CIPHER_HANDLE ctx, uint8_t * hash, size_t hash_length);

    size_t PQC_API PQC_close_context(CIPHER_HANDLE ctx);

#define PQC_LENGTH_SYMMETRIC 0
#define PQC_LENGTH_IV 1
#define PQC_LENGTH_PUBLIC 2
#define PQC_LENGTH_PRIVATE 3
#define PQC_LENGTH_SIGNATURE 4
#define PQC_LENGTH_MESSAGE 5
#define PQC_LENGTH_SHARED 6

    size_t PQC_API PQC_get_length(uint32_t cipher, uint32_t type);
    size_t PQC_API PQC_context_get_length(CIPHER_HANDLE context, uint32_t type);

#ifdef __cplusplus
}
#endif
