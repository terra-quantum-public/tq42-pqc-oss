#pragma once

#include <stdint.h>

namespace dilithium
{

#define MONT -4186625 // 2^32 % Q
#define QINV 58728449 // q^(-1) mod 2^32

int32_t montgomery_reduce(int64_t a);

int32_t reduce32(int32_t a);

int32_t caddq(int32_t a);

int32_t freeze(int32_t a);

} // namespace dilithium
