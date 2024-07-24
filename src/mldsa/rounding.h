#pragma once

#include <stdint.h>

namespace mldsa
{

int32_t power2round(int32_t * a0, int32_t a);

int32_t decompose(int32_t * a0, int32_t a);

unsigned int make_hint(int32_t a0, int32_t a1);

int32_t use_hint(int32_t a, unsigned int hint);

} // namespace mldsa
