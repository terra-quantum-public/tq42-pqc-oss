#pragma once
#include "aes.h"
#include "core.h"
#include <limits>
#include <stdint.h>

class PQ17prng_engine : public IRandomGenerator
{
public:
    PQ17prng_engine(const pqc_aes_key * key, const pqc_aes_iv * iv);

    uint64_t generate();
    void random_bytes(uint8_t * buf, size_t size) override;

    static std::unique_ptr<IRandomGenerator> default_generator();

private:
    void step();

private:
    AES aes;
    uint64_t v[2] = {0};
    uint64_t r[2] = {0};
    int next = 0;
};
