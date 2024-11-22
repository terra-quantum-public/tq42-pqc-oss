#include "external_random_generator.h"
#include "core.h"

ExternalRandomGenerator::ExternalRandomGenerator(_get_external_random get_ext_random)
    : get_external_random(get_ext_random)
{
}

void ExternalRandomGenerator::random_bytes(const BufferView & buffer)
{
    size_t result = get_external_random(buffer.data(), buffer.size());
    if (result != PQC_OK)
    {
        throw RandomFailure();
    }
}
