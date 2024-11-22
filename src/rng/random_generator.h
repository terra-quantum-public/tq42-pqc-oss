#pragma once

#include <buffer.h>
#include <cstddef>
#include <cstdint>

using std::size_t;
using std::uint8_t;

class IRandomGenerator
{
public:
    virtual void random_bytes(const BufferView & buffer) = 0;
    virtual ~IRandomGenerator() = default;
};
