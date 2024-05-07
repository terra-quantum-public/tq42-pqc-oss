#include "rng.h"

#include <buffer.h>
#include <core.h>
#include <rng/random_generator.h>


void randombytes(const BufferView & buffer)
{
    IRandomGenerator & generator = algorithm_registry.get_random_generator();
    generator.random_bytes(buffer.data(), buffer.size());
}
