#pragma once

#include "pqc/random.h"
#include "random_generator.h"

class ExternalRandomGenerator : public IRandomGenerator
{
public:
    ExternalRandomGenerator(_get_external_random get_ext_random);
    void random_bytes(uint8_t * buf, size_t size) override;

private:
    _get_external_random get_external_random;
};
