#pragma once

#include <buffer.h>


bool mceliece_8192128_f_pk_gen(
    const BufferView & pubKey, const uint32_t * perm, const ConstBufferView & secKey, int16_t * pi, uint64_t & pivots
);
