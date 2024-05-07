#pragma once

#include <vector>

#include <buffer.h>
#include <mceliece/special_utils.h>


void mceliece_8192128_f_apply_benes(const BufferView &, const ConstBufferView & bts);

void mceliece_8192128_f_support_gen(uint16_t * a, const ConstBufferView & b);
