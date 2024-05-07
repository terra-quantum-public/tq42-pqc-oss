#pragma once

#include <stdint.h>

#include "common.h"

typedef void(PQC_CALLBACK * _get_external_random)(uint8_t *, size_t);

#ifdef __cplusplus
extern "C"
{
#endif

    void PQC_API PQC_random_from_external(_get_external_random get_ext_random);
    size_t PQC_API PQC_random_from_pq_17(const uint8_t * key, size_t key_len, const uint8_t * iv, size_t iv_len);
    void PQC_API PQC_random_bytes(void * buffer, size_t length);

#ifdef __cplusplus
}
#endif
