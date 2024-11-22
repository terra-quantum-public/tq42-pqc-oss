#pragma once

#include <mldsa/params.h>
#include <stdint.h>

namespace dilithium
{

void ntt(int32_t a[N]);

void invntt_tomont(int32_t a[N]);

} // namespace dilithium
