#include "external_random_generator.h"

ExternalRandomGenerator::ExternalRandomGenerator(_get_external_random get_ext_random)
    : get_external_random(get_ext_random)
{
}

void ExternalRandomGenerator::random_bytes(uint8_t * buf, size_t size) { get_external_random(buf, size); }
