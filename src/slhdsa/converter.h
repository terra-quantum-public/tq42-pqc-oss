#pragma once

#include <buffer.h>
#include <cstddef>
#include <cstdint>

using std::size_t;
using std::uint32_t;

namespace slh_dsa
{
namespace Converter
{

// Algortihm 1
// Converts big-endian representation to integer value
size_t toInteger(const ConstBufferView & buf);

// Algortihm 2
// Stores big-endian representation of integer to buf
void toByte(BufferView & buf, size_t val);

// Algortihm 3
// Stores 2^b representation of input to output, b=4 in draft
void base_2b(int * output, const size_t out_len, const ConstBufferView & buf, int b);

} // namespace Converter
} // namespace slh_dsa
