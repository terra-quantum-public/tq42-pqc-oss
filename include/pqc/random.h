#pragma once

#include <stdint.h>

#include "common.h"

typedef size_t(PQC_CALLBACK * _get_external_random)(uint8_t *, size_t);

#ifdef __cplusplus
extern "C"
{
#endif

    size_t PQC_API PQC_context_random_set_external(CIPHER_HANDLE ctx, _get_external_random get_ext_random);
    size_t PQC_API PQC_context_random_set_pq_17(
        CIPHER_HANDLE ctx, const uint8_t * key, size_t key_len, const uint8_t * iv, size_t iv_len
    );
    size_t PQC_API PQC_context_random_get_bytes(CIPHER_HANDLE ctx, void * buffer, size_t length);

#ifdef __cplusplus
}
#endif
