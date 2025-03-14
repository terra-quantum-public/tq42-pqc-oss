#pragma once

#include <stdint.h>

#define MONT 2285  // 2^16 mod q
#define QINV 62209 // q^-1 mod 2^16


int16_t montgomery_reduce(int32_t a);

int16_t barrett_reduce(int16_t a);

int16_t csubq(int16_t x);
