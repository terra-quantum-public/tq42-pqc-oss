#include "converter.h"
#include "core.h"
#include <cmath>

namespace slh_dsa
{
namespace Converter
{

// Algortihm 1
// Converts big-endian representation to integer value
size_t toInteger(const ConstBufferView & buf)
{
    size_t retval = 0;
    const size_t len = buf.size();
    const uint8_t * in = buf.const_data();
    for (size_t i = 0; i < len; ++i)
    {
        retval |= ((size_t)in[i]) << (8 * (len - 1 - i));
    }
    return retval;
}

// Algortihm 2
// Stores big-endian representation of integer to buf
void toByte(BufferView & buf, size_t val)
{
    const size_t len = buf.size();
    uint8_t * out = buf.data();
    for (size_t i = 0; i < len; ++i)
    {
        out[len - 1 - i] = static_cast<uint8_t>(val & 0xff);
        val = val >> 8;
    }
}

// Algortihm 3
// Stores 2^b representation of input to output, b=4 in draft
void base_2b(int * output, const size_t out_len, const ConstBufferView & buf, int b)
{
    size_t size_check = (size_t)std::ceil((double)out_len * b / 8);
    if (buf.size() < size_check)
        throw InternalError();

    const uint8_t * x = buf.const_data();
    int i = 0;
    int bits = 0;
    uint32_t total = 0;
    const int base = (1L << b) - 1;

    for (size_t j = 0; j < out_len; ++j)
    {
        while (bits < b)
        {
            total = (total << 8) + x[i];
            ++i;
            bits += 8;
        }
        bits -= b;
        output[j] = static_cast<int>((total >> bits) & base);
    }
}

} // namespace Converter
} // namespace slh_dsa
