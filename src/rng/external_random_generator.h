#pragma once

#include "pqc/random.h"
#include "random_generator.h"

class ExternalRandomGenerator : public IRandomGenerator
{
public:
    ExternalRandomGenerator(_get_external_random get_ext_random);
    virtual void random_bytes(const BufferView & bufer) override;

private:
    _get_external_random get_external_random;
};
