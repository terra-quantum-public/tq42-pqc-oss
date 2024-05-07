#pragma once

#include <cstddef>
#include <cstdint>

using std::size_t;
using std::uint8_t;

class IRandomGenerator
{
public:
    virtual void random_bytes(uint8_t * buf, size_t size) = 0;
    virtual ~IRandomGenerator() = default;
};
