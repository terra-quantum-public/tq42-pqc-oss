#include "pq17.h"
#include "sha3.h"
#include <chrono>
#include <cstring>
#include <mutex>

PQ17prng_engine::PQ17prng_engine(const pqc_aes_key * key, const pqc_aes_iv * iv)
    : aes(ConstBufferView::from_single(*key), ConstBufferView::from_single(*iv))
{
}

uint64_t PQ17prng_engine::generate()
{
    if (next == 0)
    {
        step();
    }
    next = 1 - next;
    return r[next];
}

void PQ17prng_engine::random_bytes(const BufferView & buffer)
{
    auto blocks = iterate_blocks(buffer, sizeof(uint64_t));

    for (BufferView block : blocks)
    {
        block.store_64_le(0, generate());
    }

    if (blocks.has_extra())
    {
        uint64_t value = generate();
        BufferView block = blocks.extra();

        block.store(BufferView::from_single(value).mid(0, block.size()));
    }
}

std::unique_ptr<IRandomGenerator> PQ17prng_engine::default_generator()
{
    static const uint8_t default_key[PQC_AES_KEYLEN] = {200, 18,  1,   119, 214, 41,  97,  100, 69,  140, 22,
                                                        224, 221, 242, 24,  34,  73,  26,  156, 73,  5,   204,
                                                        141, 80,  14,  88,  41,  182, 155, 195, 159, 248};

    static uint8_t default_iv[PQC_AES_IVLEN] = {123, 167, 144, 196, 229, 170, 161, 4,
                                                184, 11,  151, 51,  126, 188, 178, 74};

    static std::mutex mutex;

    std::unique_lock lock(mutex);

    for (int i = 0; i < PQC_AES_IVLEN; ++i)
    {
        ++default_iv[i];
        if (default_iv[i] != 0)
        {
            break;
        }
    }

    return std::make_unique<PQ17prng_engine>((const pqc_aes_key *)default_key, (const pqc_aes_iv *)default_iv);
}

void PQ17prng_engine::step()
{
    std::chrono::system_clock::time_point current_time = std::chrono::system_clock::now();

    uint64_t dt[2] = {0};

    memcpy(dt, &current_time, std::min(sizeof(uint64_t) * 2, sizeof(current_time)));

    SHA3 sha3(PQC_SHA3_256);
    sha3.update(ConstBufferView::from_single(dt[0]));
    memcpy(dt, sha3.retrieve() + 8, sizeof(uint64_t) * 2);

    BufferView dataDT = BufferView(reinterpret_cast<uint8_t *>(dt), sizeof(uint64_t) * 2);
    aes.ofb_xcrypt(dataDT);

    r[0] = dt[0] ^ v[0];
    r[1] = dt[1] ^ v[1];
    BufferView dataR = BufferView(reinterpret_cast<uint8_t *>(&r), sizeof(uint64_t) * 2);
    aes.ofb_xcrypt(dataR);

    v[0] = r[0] ^ dt[0];
    v[1] = r[1] ^ dt[1];

    BufferView dataV = BufferView(reinterpret_cast<uint8_t *>(&v), sizeof(uint64_t) * 2);
    aes.ofb_xcrypt(dataV);
}
